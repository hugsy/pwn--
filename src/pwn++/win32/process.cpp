#include "win32/process.hpp"

#include <accctrl.h>
#include <aclapi.h>
#include <psapi.h>
#include <sddl.h>
#include <shellapi.h>
#include <tlhelp32.h>
#include <userenv.h>

#include <filesystem>
#include <stdexcept>
#include <utility>

#include "handle.hpp"
#include "log.hpp"
#include "thread.hpp"
#include "utils.hpp"
#include "win32/system.hpp"

IMPORT_EXTERNAL_FUNCTION(L"ntdll.dll", NtWow64ReadVirtualMemory64, NTSTATUS, HANDLE, PVOID64, PVOID, ULONG64, PULONG64);

IMPORT_EXTERNAL_FUNCTION(
    L"ntdll.dll",
    NtWow64WriteVirtualMemory64,
    NTSTATUS,
    HANDLE,
    PVOID64,
    PVOID,
    ULONG64,
    PULONG64);

IMPORT_EXTERNAL_FUNCTION(
    L"ntdll.dll",
    NtWow64QueryInformationProcess64,
    NTSTATUS,
    HANDLE,
    PROCESSINFOCLASS,
    PVOID,
    ULONG,
    PULONG);


EXTERN_C_START
#ifndef _M_ARM64
bool
GetPeb(uptr* peb);

usize
GetPebLength();
#else
bool
GetPeb(uptr* peb)
{
    return false;
}

usize
GetPebLength()
{
    return 0;
}
#endif // _M_ARM64
EXTERN_C_END


namespace pwn::windows
{

#pragma region Process::Memory

Result<std::vector<u8>>
Process::Memory::Read(uptr const Address, usize Length)
{
    if ( !m_Process || !m_ProcessHandle )
    {
        return Err(ErrorCode::NotInitialized);
    }

    auto out = std::vector<u8>(Length);
    usize dwNbRead;
    if ( ::ReadProcessMemory(
             m_ProcessHandle->get(),
             reinterpret_cast<LPVOID>(Address),
             out.data(),
             Length,
             &dwNbRead) == false )
    {
        return Err(ErrorCode::ExternalApiCallFailed);
    }

    return Ok(out);
}

Result<usize>
Process::Memory::Memset(uptr const address, const size_t size, const u8 val)
{
    auto data = std::vector<u8>(size);
    std::fill(data.begin(), data.end(), val);
    return Write(address, data);
}

Result<usize>
Process::Memory::Write(uptr const Address, std::vector<u8> data)
{
    if ( !m_Process || !m_ProcessHandle )
    {
        return Err(ErrorCode::NotInitialized);
    }

    usize dwNbWritten;
    if ( ::WriteProcessMemory(
             m_ProcessHandle->get(),
             reinterpret_cast<LPVOID>(Address),
             data.data(),
             data.size(),
             &dwNbWritten) != false )
    {
        return Err(ErrorCode::ExternalApiCallFailed);
    }

    return Ok(dwNbWritten);
}

Result<uptr>
Process::Memory::Allocate(const size_t Size, const wchar_t Permission[3], const uptr ForcedMappingAddress, bool wipe)
{
    if ( !m_Process || !m_ProcessHandle )
    {
        return Err(ErrorCode::NotInitialized);
    }

    u32 flProtect = 0;
    if ( wcscmp(Permission, L"r") == 0 )
    {
        flProtect |= PAGE_READONLY;
    }
    if ( wcscmp(Permission, L"rx") == 0 )
    {
        flProtect |= PAGE_EXECUTE_READ;
    }
    if ( wcscmp(Permission, L"rw") == 0 )
    {
        flProtect |= PAGE_READWRITE;
    }
    if ( wcscmp(Permission, L"rwx") == 0 )
    {
        flProtect |= PAGE_EXECUTE_READWRITE;
    }

    auto buffer = (uptr)::VirtualAllocEx(
        m_ProcessHandle->get(),
        nullptr,
        Size,
        MEM_COMMIT | MEM_RESERVE,
        flProtect ? flProtect : PAGE_GUARD);
    if ( buffer == 0u )
    {
        return Err(ErrorCode::AllocationError);
    }

    if ( wipe )
    {
        Memset(buffer, Size, 0x00);
    }

    return Ok(buffer);
}

bool
Process::Memory::Free(const uptr Address)
{
    return ::VirtualFreeEx(m_ProcessHandle->get(), reinterpret_cast<LPVOID>(Address), 0, MEM_RELEASE) == 0;
}

Result<PVOID>
Process::Memory::QueryInternal(
    const MEMORY_INFORMATION_CLASS MemoryInformationClass,
    const uptr BaseAddress,
    const usize InitialSize)
{
    usize Size  = InitialSize;
    auto Buffer = ::LocalAlloc(LPTR, Size);
    if ( !Buffer )
    {
        return Err(ErrorCode::AllocationError);
    }

    do
    {
        usize ReturnLength = 0;
        NTSTATUS Status    = ::NtQueryVirtualMemory(
            m_ProcessHandle->get(),
            (PVOID)BaseAddress,
            MemoryInformationClass,
            Buffer,
            Size,
            &ReturnLength);
        if ( NT_SUCCESS(Status) )
        {
            break;
        }

        if ( Status == STATUS_INFO_LENGTH_MISMATCH )
        {
            Size   = ReturnLength;
            Buffer = ::LocalReAlloc(Buffer, Size, LMEM_ZEROINIT);
            continue;
        }

        log::ntperror(L"NtQueryVirtualMemory()", Status);

        //
        // If doing an iteration, the last address will be invalid
        // resulting in having STATUS_INVALID_PARAMETER. We just exit.
        //
        if ( Status == STATUS_INVALID_PARAMETER )
        {
            return Err(ErrorCode::InvalidParameter);
        }

        return Err(ErrorCode::PermissionDenied);

    } while ( true );

    return Ok(Buffer);
}

Result<std::vector<std::shared_ptr<MEMORY_BASIC_INFORMATION>>>
Process::Memory::Regions()
{
    uptr CurrentAddress = 0;
    std::vector<std::shared_ptr<MEMORY_BASIC_INFORMATION>> MemoryRegions;

    while ( true )
    {
        //
        // Query the location
        //
        auto res = Query<MEMORY_BASIC_INFORMATION>(MemoryBasicInformation, CurrentAddress);
        if ( Failed(res) )
        {
            auto e = Error(res);
            if ( e.code == ErrorCode::InvalidParameter )
            {
                break;
            }

            return Err(e.code);
        }

        //
        // Save the region information
        //
        auto CurrentMemoryRegion = Value(res);
        if ( CurrentMemoryRegion->BaseAddress != nullptr )
        {
            MemoryRegions.push_back(CurrentMemoryRegion);
        }

        //
        // Move to the next one
        //
        CurrentAddress += CurrentMemoryRegion->RegionSize;
    }

    return Ok(MemoryRegions);
}

Result<std::vector<uptr>>
Process::Memory::Search(std::vector<u8> const& Pattern)
{
    if ( Pattern.empty() )
    {
        return Err(ErrorCode::BufferTooSmall);
    }

    auto res = Regions();
    if ( Failed(res) )
    {
        return Err(Error(res).code);
    }

    std::vector<uptr> Matches;

    for ( auto const& Region : Value(res) )
    {
        if ( Region->State != MEM_COMMIT )
        {
            continue;
        }

        if ( (Region->Protect != PAGE_READONLY) && (Region->Protect != PAGE_READWRITE) &&
             (Region->Protect != PAGE_EXECUTE_READWRITE) )
        {
            continue;
        }

        const uptr StartAddress = (uptr)Region->BaseAddress;
        const usize Size        = Region->RegionSize;

        if ( Size < Pattern.size() )
        {
            continue;
        }

        auto res = Read(StartAddress, Size);
        if ( Failed(res) )
        {
            continue;
        }

        auto const& RemoteMemoryRegion = Value(res);
        usize CurrentIndex             = 0;
        const usize MaxSize            = RemoteMemoryRegion.size() - Pattern.size();

        while ( CurrentIndex < MaxSize )
        {
            usize Offset = 0;

            for ( auto const& c : Pattern )
            {
                if ( c != RemoteMemoryRegion[CurrentIndex + Offset] )
                {
                    break;
                }

                Offset++;
            }

            if ( Offset == 0 )
            {
                CurrentIndex++;
                continue;
            }

            if ( Offset == Pattern.size() )
            {
                const uptr MatchingAddress = (uptr)(StartAddress + CurrentIndex);
                Matches.push_back(MatchingAddress);
            }

            CurrentIndex += Offset;
        }
    }
    return Ok(Matches);
}

#pragma endregion Process::Memory


#pragma region Process::ThreadGroup

Result<std::vector<u32>>
Process::ThreadGroup::List()
{
    if ( !m_Process )
    {
        return Err(ErrorCode::NotInitialized);
    }

    auto h = UniqueHandle {::CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0)};
    if ( !h )
    {
        log::perror(L"CreateToolhelp32Snapshot()");
        return Err(ErrorCode::ExternalApiCallFailed);
    }

    std::vector<u32> tids;
    const u32 Pid    = m_Process->ProcessId();
    THREADENTRY32 te = {0};
    te.dwSize        = sizeof(te);
    if ( ::Thread32First(h.get(), &te) )
    {
        do
        {
            if ( !(te.dwSize >= FIELD_OFFSET(THREADENTRY32, th32OwnerProcessID) + sizeof(te.th32OwnerProcessID)) )
                continue;
            if ( !te.th32ThreadID )
                continue;

            if ( te.th32OwnerProcessID != Pid )
                continue;

            tids.push_back(te.th32ThreadID);

            te.dwSize = sizeof(te);
        } while ( ::Thread32Next(h.get(), &te) );
    }

    return Ok(tids);
}

Thread
Process::ThreadGroup::at(const u32 Tid)
{
    if ( !m_Process )
    {
        throw std::runtime_error("Thread initialization failed");
    }

    auto res = List();
    if ( Failed(res) )
    {
        throw std::runtime_error("Thread enumeration failed");
    }

    const auto tids = Value(res);
    if ( std::find(tids.cbegin(), tids.cend(), Tid) == std::end(tids) )
    {
        throw std::range_error("Invalid thread Id");
    }

    return Thread(Tid, m_Process);
}

Thread
Process::ThreadGroup::operator[](u32 Tid)
{
    return at(Tid);
}

#pragma endregion Process::ThreadGroup

#pragma region Process


Process::Process(u32 pid, HANDLE hProcess, bool kill_on_delete) :
    m_Pid {pid},
    m_Peb {nullptr},
    m_Valid {true},
    m_ProcessHandleAccessMask {0}
{
    //
    // Gather a minimum set of information about the process for performance. Extra information will be
    // lazily fetched
    //
    try
    {
        m_IsSelf      = (m_Pid == ::GetCurrentProcessId());
        m_KillOnClose = m_IsSelf ? false : kill_on_delete;

        // Get a handle to the "real process"
        {
            m_ProcessHandle = std::make_shared<UniqueHandle>(pwn::UniqueHandle {hProcess});

            if ( Failed(ReOpenProcessWith(PROCESS_QUERY_INFORMATION)) &&
                 Failed(ReOpenProcessWith(PROCESS_QUERY_LIMITED_INFORMATION)) )
            {
                m_Valid = false;
                return;
            }
        }

        // WOW64
        {
            BOOL bIsWow = FALSE;
            if ( FALSE == ::IsWow64Process(m_ProcessHandle->get(), &bIsWow) )
            {
                m_Valid = false;
                return;
            }

            m_IsWow64 = (bIsWow == TRUE);
        }

        // Process PPID
        {
            auto ppid = pwn::windows::System::ParentProcessId(pid);
            m_Ppid    = ppid ? ppid.value() : -1;
        }

        // Full path
        {
            wchar_t exeName[MAX_PATH] = {0};
            DWORD size                = __countof(exeName);
            DWORD count               = ::QueryFullProcessImageName(m_ProcessHandle->get(), 0, exeName, &size);

            m_Path = fs::path {exeName};
        }

        // Prepare other subclasses
        {
            // Memory
            {
                if ( Failed(ReOpenProcessWith(PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE)) )
                {
                    m_Valid = false;
                    return;
                }

                this->Memory = windows::Process::Memory::Memory(this);
            }

            // Token
            {
                this->Token = windows::Token(m_ProcessHandle, Token::TokenType::Process);
            }

            // Threads
            {
                this->m_Threads = windows::Process::ThreadGroup(std::make_shared<Process>(*this));
            }

            m_Valid = true;
        }
    }
    catch ( ... )
    {
        m_Valid = false;
    }
}

Process::~Process()
{
    if ( m_Valid && m_KillOnClose && !m_IsSelf )
    {
        Kill();
    }
}

Process::Process(Process const& Copy) :
    m_Valid {Copy.m_Valid},
    m_Pid {Copy.m_Pid},
    m_Ppid {Copy.m_Ppid},
    m_Path {Copy.m_Path},
    m_IntegrityLevel {Copy.m_IntegrityLevel},
    m_ProcessHandle {Copy.m_ProcessHandle},
    m_ProcessHandleAccessMask {Copy.m_ProcessHandleAccessMask},
    m_KillOnClose {Copy.m_KillOnClose},
    m_IsSelf {Copy.m_IsSelf},
    m_Peb {Copy.m_Peb},
    m_Threads {Copy.m_Threads}
{
    Token  = windows::Token(m_ProcessHandle, windows::Token::TokenType::Process);
    Memory = windows::Process::Memory::Memory(this);
}


Process&
Process::operator=(Process const& Copy)
{
    m_Valid                   = Copy.m_Valid;
    m_Pid                     = Copy.m_Pid;
    m_Ppid                    = Copy.m_Ppid;
    m_Path                    = Copy.m_Path;
    m_IntegrityLevel          = Copy.m_IntegrityLevel;
    m_ProcessHandle           = Copy.m_ProcessHandle;
    m_ProcessHandleAccessMask = Copy.m_ProcessHandleAccessMask;
    m_KillOnClose             = Copy.m_KillOnClose;
    m_IsSelf                  = Copy.m_IsSelf;
    m_Peb                     = Copy.m_Peb;
    m_Threads                 = Copy.m_Threads;

    Token  = windows::Token(m_ProcessHandle, windows::Token::TokenType::Process);
    Memory = windows::Process::Memory::Memory(this);
    return *this;
}

bool
Process::IsValid()
{
    return m_Valid;
}

u32 const
Process::ParentProcessId() const
{
    return m_Ppid;
}

u32 const
Process::ProcessId() const
{
    return m_Pid;
}

fs::path const&
Process::Path() const
{
    return m_Path;
}


PPEB
Process::ProcessEnvironmentBlock()
{
    //
    // If already fetched, don't need to recalculate it
    //
    if ( m_Peb )
    {
        return m_Peb;
    }

    //
    // If local, easy
    //
    if ( m_IsSelf )
    {
        uptr peb = 0;
        if ( GetPeb(&peb) == true )
        {
            m_Peb = (PPEB)peb;
        }
    }
    else
    {
        //
        // Otherwise execute the function remotely
        //

        //
        // Copy the function from the local process to the remote
        //
        const uptr pfnGetPeb     = (uptr)&GetPeb;
        const usize pfnGetPebLen = GetPebLength();

        auto res = Execute(pfnGetPeb, pfnGetPebLen);
        if ( Success(res) )
        {
            m_Peb = reinterpret_cast<PPEB>(Value(res));
        }
    }

    //
    // Check for success
    //
    if ( !m_Peb )
    {
        warn(L"PEB was not found");
    }

    return m_Peb;
}


Result<uptr>
Process::Execute(uptr const CodePointer, usize const CodePointerSize)
{
    uptr Result                = 0;
    const usize AllocationSize = CodePointerSize + sizeof(uptr);
    const std::vector<u8> sc(CodePointerSize);
    RtlCopyMemory((void*)sc.data(), (void*)CodePointer, CodePointerSize);

    //
    // Allocate the memory and copy the code
    //
    auto res = Memory.Allocate(AllocationSize, L"rwx");
    if ( Failed(res) )
    {
        return Err(ErrorCode::AllocationError);
    }

    auto const Target = Value(res);
    Memory.Memset(Target, AllocationSize);
    Memory.Write(Target, sc);

    //
    // Execute it
    //
    {
        DWORD ExitCode = 0;
        auto hThread   = pwn::UniqueHandle {::CreateRemoteThreadEx(
            m_ProcessHandle->get(),
            nullptr,
            0,
            reinterpret_cast<LPTHREAD_START_ROUTINE>(Target),
            (LPVOID)(Target + CodePointerSize),
            0,
            nullptr,
            nullptr)};

        ::WaitForSingleObject(hThread.get(), INFINITE);
        if ( ::GetExitCodeThread(hThread.get(), &ExitCode) && ExitCode == 1 )
        {
            auto res2 = Memory.Read(Target + CodePointerSize, sizeof(uptr));
            if ( Success(res2) )
            {
                Result = (*(uptr*)(Value(res2).data()));
            }
        }
    }
    Memory.Free(Target);

    return Ok(Result);
}


std::wostream&
operator<<(std::wostream& wos, const Process::Integrity i)
{
    switch ( i )
    {
    case Process::Integrity::Low:
        wos << L"INTEGRITY_LOW";
        break;

    case Process::Integrity::Medium:
        wos << L"INTEGRITY_MEDIUM";
        break;

    case Process::Integrity::High:
        wos << L"INTEGRITY_HIGH";
        break;

    case Process::Integrity::System:
        wos << L"INTEGRITY_SYSTEM";
        break;

    default:
        wos << L"INTEGRITY_UNKNOWN";
        break;
    }
    return wos;
}


Result<bool>
Process::Kill()
{
    if ( !IsValid() )
    {
        return Err(ErrorCode::InvalidState);
    }

    if ( Failed(ReOpenProcessWith(PROCESS_TERMINATE)) )
    {
        return Err(ErrorCode::PermissionDenied);
    }

    dbg(L"Attempting to kill PID={})", m_Pid);
    bool bRes = (::TerminateProcess(m_ProcessHandle->get(), EXIT_FAILURE) == TRUE);
    if ( !bRes )
    {
        log::perror(L"TerminateProcess()");
        return Err(ErrorCode::ExternalApiCallFailed);
    }

    m_Valid = false;
    return Ok(bRes);
}


Result<std::vector<Process>>
Processes()
{
    u16 maxCount = 256;
    std::unique_ptr<DWORD[]> pids;
    int count = 0;
    std::vector<Process> processes;

    for ( ;; )
    {
        pids = std::make_unique<DWORD[]>(maxCount);
        DWORD actualSize;
        if ( ::EnumProcesses((PDWORD)pids.get(), maxCount * sizeof(DWORD), &actualSize) == 0 )
        {
            break;
        }

        count = actualSize / sizeof(u32);

        if ( count < maxCount )
        {
            break; // need to resize
        }

        maxCount *= 2;
    }

    for ( int i = 0; i < count; i++ )
    {
        const u32 pid = pids[i];
        auto p        = Process(pid);
        if ( !p.IsValid() )
        {
            continue;
        }

        processes.push_back(std::move(p));
    }

    return Ok(processes);
}


Result<Process::Integrity>
Process::IntegrityLevel()
{
    //
    // Check from the cache
    //
    if ( m_IntegrityLevel != Process::Integrity::Unknown )
    {
        return Ok(m_IntegrityLevel);
    }

    //
    // Otherwise try to determine it
    //
    auto hProcessHandle = pwn::UniqueHandle {::OpenProcess(PROCESS_QUERY_INFORMATION, false, m_Pid)};
    if ( !hProcessHandle )
    {
        return Err(ErrorCode::InvalidProcess);
    }

    auto hProcessToken = pwn::UniqueHandle(
        [&]() -> HANDLE
        {
            HANDLE h;
            return (::OpenProcessToken(hProcessHandle.get(), TOKEN_ADJUST_PRIVILEGES, &h) == TRUE) ? h : nullptr;
        }());
    if ( !hProcessToken )
    {
        return Err(ErrorCode::PermissionDenied);
    }

    DWORD dwLengthNeeded = 0;
    if ( (::GetTokenInformation(hProcessToken.get(), TokenIntegrityLevel, nullptr, 0, &dwLengthNeeded) == false) ||
         (::GetLastError() != ERROR_INSUFFICIENT_BUFFER) )
    {
        return Err(ErrorCode::ExternalApiCallFailed);
    }

    auto pTokenBuffer = std::make_unique<TOKEN_MANDATORY_LABEL[]>(dwLengthNeeded);
    if ( ::GetTokenInformation(
             hProcessToken.get(),
             TokenIntegrityLevel,
             pTokenBuffer.get(),
             dwLengthNeeded,
             &dwLengthNeeded) == false )
    {
        return Err(ErrorCode::ExternalApiCallFailed);
    }

    u32 dwIntegrityLevel = *::GetSidSubAuthority(
        pTokenBuffer.get()->Label.Sid,
        (u32)(UCHAR)(*::GetSidSubAuthorityCount(pTokenBuffer.get()->Label.Sid) - 1));

    if ( dwIntegrityLevel == SECURITY_MANDATORY_LOW_RID )
    {
        m_IntegrityLevel = Process::Integrity::Low;
    }
    else if ( SECURITY_MANDATORY_MEDIUM_RID <= dwIntegrityLevel && dwIntegrityLevel < SECURITY_MANDATORY_HIGH_RID )
    {
        m_IntegrityLevel = Process::Integrity::Medium;
    }
    else if ( dwIntegrityLevel == SECURITY_MANDATORY_HIGH_RID )
    {
        m_IntegrityLevel = Process::Integrity::High;
    }
    else if ( dwIntegrityLevel == SECURITY_MANDATORY_SYSTEM_RID )
    {
        m_IntegrityLevel = Process::Integrity::System;
    }

    return m_IntegrityLevel;
}


Result<Process>
Process::Current()
{
    auto p = Process(::GetCurrentProcessId(), ::GetCurrentProcess(), false);
    if ( !p.IsValid() )
    {
        return Err(ErrorCode::InitializationFailed);
    }
    return Ok(p);
}


Result<Process>
Process::New(const std::wstring_view& CommandLine, const u32 ParentPid)
{
    std::unique_ptr<u8[]> AttributeList;
    pwn::UniqueHandle hParentProcess;
    STARTUPINFOEX si = {
        {0},
    };
    PROCESS_INFORMATION pi = {0};
    const u32 dwFlags      = EXTENDED_STARTUPINFO_PRESENT | CREATE_NEW_CONSOLE;
    si.StartupInfo.cb      = sizeof(STARTUPINFOEX);

    if ( ParentPid )
    {
        HANDLE hProcess = ::OpenProcess(PROCESS_CREATE_PROCESS, false, ParentPid);
        if ( hProcess )
        {
            usize AttrListSize = 0;
            ::InitializeProcThreadAttributeList(nullptr, 1, 0, &AttrListSize);
            AttributeList = std::make_unique<u8[]>(AttrListSize);
            if ( AttributeList )
            {
                si.lpAttributeList = reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(AttributeList.get());
                ::InitializeProcThreadAttributeList(si.lpAttributeList, 1, 0, &AttrListSize);
                ::UpdateProcThreadAttribute(
                    si.lpAttributeList,
                    0,
                    PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,
                    &hProcess,
                    sizeof(HANDLE),
                    nullptr,
                    nullptr);
                dbg(L"Spawning '{}' with PPID={}...", CommandLine, ParentPid);
            }

            hParentProcess = pwn::UniqueHandle {hProcess};
        }
        else
        {
            log::perror(L"OpenProcess()");
        }
    }
    else
    {
        dbg(L"Spawning '{}'...", CommandLine);
    }

    if ( ::CreateProcessW(
             nullptr,
             (LPWSTR)(CommandLine.data()),
             nullptr,
             nullptr,
             1,
             dwFlags,
             nullptr,
             nullptr,
             reinterpret_cast<LPSTARTUPINFO>(&si),
             &pi) == FALSE )
    {
        log::perror(L"CreateProcess()");
        return Err(ErrorCode::RuntimeError);
    }

    if ( hParentProcess )
    {
        if ( si.lpAttributeList != nullptr )
        {
            ::DeleteProcThreadAttributeList(si.lpAttributeList);
        }
    }

    dbg(L"'{}' spawned with PID {}", CommandLine, pi.dwProcessId);

    ::CloseHandle(pi.hThread);

    auto p = Process(pi.dwProcessId, pi.hProcess);
    if ( !p.IsValid() )
    {
        return Err(ErrorCode::AllocationError);
    }
    return Ok(p);
}


Result<bool>
Process::ReOpenProcessWith(const DWORD DesiredAccess)
{
    if ( !IsValid() )
    {
        return Err(ErrorCode::InvalidState);
    }

    //
    // If we already have the sufficient rights, skip
    //
    if ( (m_ProcessHandleAccessMask & DesiredAccess) == DesiredAccess )
    {
        return Ok(true);
    }

    //
    // Otherwise, try to get it
    //
    u32 NewAccessMask = m_ProcessHandleAccessMask | DesiredAccess;
    HANDLE hProcess   = ::OpenProcess(NewAccessMask, false, m_Pid);
    if ( hProcess == nullptr )
    {
        log::perror(L"OpenProcess()");
        return Err(ErrorCode::PermissionDenied);
    }

    SharedHandle New = std::make_shared<UniqueHandle>(pwn::UniqueHandle {hProcess});
    m_ProcessHandle.swap(New);
    m_ProcessHandleAccessMask = NewAccessMask;
    return Ok(true);
}

Result<PVOID>
Process::QueryInternal(const PROCESSINFOCLASS ProcessInformationClass, const usize InitialSize)
{
    usize Size         = InitialSize;
    ULONG ReturnLength = 0;
    NTSTATUS Status    = STATUS_SUCCESS;
    auto Buffer        = ::LocalAlloc(LPTR, Size);
    if ( !Buffer )
    {
        return Err(ErrorCode::AllocationError);
    }

    do
    {
        Status =
            m_IsWow64 ?
                NtWow64QueryInformationProcess64(
                    m_ProcessHandle->get(),
                    ProcessInformationClass,
                    Buffer,
                    Size,
                    &ReturnLength) :
                NtQueryInformationProcess(m_ProcessHandle->get(), ProcessInformationClass, Buffer, Size, &ReturnLength);
        if ( NT_SUCCESS(Status) )
        {
            break;
        }

        if ( Status == STATUS_INFO_LENGTH_MISMATCH )
        {
            Size   = ReturnLength;
            Buffer = ::LocalReAlloc(Buffer, Size, LMEM_ZEROINIT);
            continue;
        }

        log::ntperror(L"NtQueryInformationProcess()", Status);
        return Err(ErrorCode::PermissionDenied);

    } while ( true );

    return Ok(Buffer);
}

#pragma endregion Process

Result<bool>
System(_In_ const std::wstring& CommandLine, _In_ const std::wstring& Operation)
{
    auto args = pwn::utils::split(CommandLine, L' ');
    auto cmd {args[0]};
    args.erase(args.begin());
    auto params  = pwn::utils::join(args);
    bool success = static_cast<bool>(
        reinterpret_cast<long long>(
            ::ShellExecuteW(nullptr, Operation.c_str(), cmd.c_str(), params.c_str(), nullptr, SW_SHOW)) > 32);
    return Ok(success);
}


#pragma region AppContainer

AppContainer::AppContainer(
    std::wstring_view const& container_name,
    std::wstring_view const& executable_path,
    std::vector<WELL_KNOWN_SID_TYPE> const& desired_capabilities) :
    m_ExecutablePath(executable_path),
    m_ContainerName(container_name),
    m_Capabilities(desired_capabilities)
{
    auto hRes = ::CreateAppContainerProfile(
        m_ContainerName.c_str(),
        m_ContainerName.c_str(),
        m_ContainerName.c_str(),
        nullptr,
        0,
        &m_AppContainerSid);

    if ( FAILED(hRes) )
    {
        hRes = ::DeriveAppContainerSidFromAppContainerName(m_ContainerName.c_str(), &m_AppContainerSid);
        if ( FAILED(hRes) )
        {
            throw std::runtime_error("DeriveAppContainerSidFromAppContainerName() failed");
        }
    }

    //
    // Get the SID
    //
    PWSTR str;
    ::ConvertSidToStringSid(m_AppContainerSid, &str);
    m_SidAsString = str;
    ::LocalFree(str);

    dbg(L"sid={}", m_SidAsString.c_str());

    //
    // Get the folder path
    //
    PWSTR path;
    if ( SUCCEEDED(::GetAppContainerFolderPath(m_SidAsString.c_str(), &path)) )
    {
        m_FolderPath = path;
        ::CoTaskMemFree(path);
    }

    dbg(L"folder_path={}", m_FolderPath.c_str());


    //
    // set the capabilities if any
    //
    m_SecurityCapabilities.AppContainerSid = m_AppContainerSid;
    auto dwNumberOfDesiredAttributes       = (u32)m_Capabilities.size();

    if ( dwNumberOfDesiredAttributes != 0u )
    {
        //
        // populate the entries
        //
        auto dwNumberOfValidDesiredAttributes = 0;
        auto DesiredAttributes                = std::make_unique<SID_AND_ATTRIBUTES[]>(dwNumberOfDesiredAttributes);
        for ( size_t i = 0; i < dwNumberOfDesiredAttributes; i++ )
        {
            auto& Attribute = DesiredAttributes[i];
            auto Sid        = std::make_unique<u8[]>(SECURITY_MAX_SID_SIZE);
            DWORD cbSid     = SECURITY_MAX_SID_SIZE;
            if ( ::CreateWellKnownSid(m_Capabilities.at(i), nullptr, Sid.get(), &cbSid) == 0 )
            {
                continue;
            }

            Attribute.Attributes = SE_GROUP_ENABLED;
            Attribute.Sid        = (PSID) new u8[cbSid];
            ::RtlCopyMemory(Attribute.Sid, Sid.get(), cbSid);
            dwNumberOfValidDesiredAttributes++;
        }


        //
        // fill up the security capabilities
        //

        if ( dwNumberOfValidDesiredAttributes != 0 )
        {
            m_SecurityCapabilities.CapabilityCount = dwNumberOfValidDesiredAttributes;
            m_SecurityCapabilities.Capabilities =
                (PSID_AND_ATTRIBUTES) new u8[dwNumberOfValidDesiredAttributes * sizeof(SID_AND_ATTRIBUTES)];
            ::RtlCopyMemory(
                m_SecurityCapabilities.Capabilities,
                DesiredAttributes.get(),
                dwNumberOfValidDesiredAttributes * sizeof(SID_AND_ATTRIBUTES));
        }
    }


    //
    // build the startup info
    //
    usize size = 0;
    ::InitializeProcThreadAttributeList(nullptr, 1, 0, &size);
    if ( size == 0u )
    {
        throw std::runtime_error("InitializeProcThreadAttributeList() failed");
    }

    m_StartupInfo.StartupInfo.cb  = sizeof(STARTUPINFOEX);
    m_StartupInfo.lpAttributeList = (LPPROC_THREAD_ATTRIBUTE_LIST)::new u8[size];

    if ( ::InitializeProcThreadAttributeList(m_StartupInfo.lpAttributeList, 1, 0, &size) == 0 )
    {
        throw std::runtime_error("InitializeProcThreadAttributeList() failed");
    }

    if ( ::UpdateProcThreadAttribute(
             m_StartupInfo.lpAttributeList,
             0,
             PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES,
             &m_SecurityCapabilities,
             sizeof(m_SecurityCapabilities),
             nullptr,
             nullptr) == 0 )
    {
        throw std::runtime_error("UpdateProcThreadAttribute() failed");
    }
}


AppContainer::~AppContainer()
{
    dbg(L"freeing container '{}'\n", m_SidAsString.c_str());

    if ( m_SecurityCapabilities.CapabilityCount != 0u )
    {
        for ( u32 i = 0; i < m_SecurityCapabilities.CapabilityCount; i++ )
        {
            delete[] m_SecurityCapabilities.Capabilities[i].Sid;
        }
        delete[] (u8*)m_SecurityCapabilities.Capabilities;
    }

    if ( m_StartupInfo.lpAttributeList != nullptr )
    {
        delete[] (u8*)m_StartupInfo.lpAttributeList;
    }

    if ( m_AppContainerSid != nullptr )
    {
        ::FreeSid(m_AppContainerSid);
    }
}


_Success_(return)
auto
AppContainer::allow_file_or_directory(_In_ const std::wstring& file_or_directory_name) -> bool
{
    return set_named_object_access(file_or_directory_name, SE_FILE_OBJECT, GRANT_ACCESS, FILE_ALL_ACCESS);
}


_Success_(return)
auto
AppContainer::allow_registry_key(_In_ const std::wstring& regkey) -> bool
{
    return set_named_object_access(regkey, SE_REGISTRY_KEY, GRANT_ACCESS, FILE_ALL_ACCESS);
}


_Success_(return)
auto
AppContainer::spawn() -> bool
{
    auto length     = m_ExecutablePath.length();
    auto sz         = length * 2;
    auto lpwCmdLine = std::make_unique<WCHAR[]>(sz + 2);
    ::ZeroMemory(lpwCmdLine.get(), sz + 2);
    ::memcpy(lpwCmdLine.get(), m_ExecutablePath.c_str(), sz);

    dbg(L"launching '{}' in container '{}'\n", lpwCmdLine.get(), m_SidAsString.c_str());

    auto bRes = ::CreateProcessW(
        nullptr,
        (LPWSTR)lpwCmdLine.get(),
        nullptr,
        nullptr,
        0,
        EXTENDED_STARTUPINFO_PRESENT,
        nullptr,
        nullptr,
        (LPSTARTUPINFO)&m_StartupInfo,
        &m_ProcessInfo);

    if ( m_StartupInfo.lpAttributeList != nullptr )
    {
        ::DeleteProcThreadAttributeList(m_StartupInfo.lpAttributeList);
    }

    return bRes;
}


_Success_(return)
auto
AppContainer::set_named_object_access(
    const std::wstring& ObjectName,
    const SE_OBJECT_TYPE ObjectType,
    const ACCESS_MODE AccessMode,
    const ACCESS_MASK AccessMask) -> bool
{
    bool bRes    = FALSE;
    PACL pOldAcl = nullptr;
    PACL pNewAcl = nullptr;
    u32 dwRes;
    EXPLICIT_ACCESS Access;
    PSECURITY_DESCRIPTOR pSD = nullptr;

    do
    {
        //
        // Get the old ACEs
        //
        dwRes = ::GetNamedSecurityInfoW(
            (LPWSTR)ObjectName.c_str(),
            ObjectType,
            DACL_SECURITY_INFORMATION,
            nullptr,
            nullptr,
            &pOldAcl,
            nullptr,
            &pSD);
        if ( dwRes != ERROR_SUCCESS )
        {
            break;
        }

        //
        // Build the new one
        //
        ZeroMemory(&Access, sizeof(EXPLICIT_ACCESS));
        Access.grfAccessMode                    = AccessMode;
        Access.grfAccessPermissions             = AccessMask;
        Access.grfInheritance                   = OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE;
        Access.Trustee.MultipleTrusteeOperation = NO_MULTIPLE_TRUSTEE;
        Access.Trustee.pMultipleTrustee         = nullptr;
        Access.Trustee.ptstrName                = (PWSTR)m_AppContainerSid;
        Access.Trustee.TrusteeForm              = TRUSTEE_IS_SID;
        Access.Trustee.TrusteeType              = TRUSTEE_IS_GROUP;

        dwRes = ::SetEntriesInAcl(1, &Access, pOldAcl, &pNewAcl);
        if ( dwRes != ERROR_SUCCESS )
        {
            break;
        }

        //
        // Apply to the object
        //
        dbg(L"{} access to object '{}' by container '{}'\n",
            AccessMode == GRANT_ACCESS ? L"Allowing" : L"Denying",
            ObjectName,
            m_SidAsString.c_str());
        dwRes = ::SetNamedSecurityInfoW(
            (LPWSTR)ObjectName.c_str(),
            ObjectType,
            DACL_SECURITY_INFORMATION,
            nullptr,
            nullptr,
            pNewAcl,
            nullptr);
        if ( dwRes != ERROR_SUCCESS )
        {
            break;
        }


        //
        // Keep a reference to the old ACL so we can restore the original ACEs
        //
        m_OriginalAcls.emplace_back(ObjectName, ObjectType, pOldAcl);

        bRes = TRUE;
    } while ( 0 );

    if ( pNewAcl != nullptr )
    {
        ::LocalFree(pNewAcl);
    }

    if ( pSD != nullptr )
    {
        ::LocalFree(pSD);
    }

    return bRes;
}


_Success_(return)
auto
AppContainer::join(_In_ const u32 dwTimeout) -> bool
{
    return ::WaitForSingleObject(m_ProcessInfo.hProcess, dwTimeout) != WAIT_OBJECT_0;
}


_Success_(return)
auto
AppContainer::restore_acls() -> bool
{
    bool bRes = TRUE;

    for ( auto& acl : m_OriginalAcls )
    {
        auto const& ObjectName = std::get<0>(acl);
        auto const& ObjectType = std::get<1>(acl);
        auto const& pOldAcl    = std::get<2>(acl);
        dbg(L"restoring original acl for '{}'", ObjectName.c_str());
        bRes &= static_cast<bool>(
            ::SetNamedSecurityInfoW(
                (PWSTR)ObjectName.c_str(),
                ObjectType,
                DACL_SECURITY_INFORMATION,
                nullptr,
                nullptr,
                pOldAcl,
                nullptr) == ERROR_SUCCESS);
    }

    return bRes;
}
#pragma endregion AppContainer

} // namespace pwn::windows
