#include "win32/process.hpp"

#include "log.hpp"
#include "win32/system.hpp"

using namespace pwn::log;

#include <accctrl.h>
#include <aclapi.h>
#include <psapi.h>
#include <sddl.h>
#include <shellapi.h>
#include <userenv.h>

#include <filesystem>
#include <stdexcept>
#include <utility>

#include "handle.hpp"
#include "utils.hpp"

namespace fs = std::filesystem;

static const std::array<pwn::windows::process::Process::Privilege, 37> PrivilegeNames = {
    L"SeAssignPrimaryTokenPrivilege",
    L"SeAuditPrivilege",
    L"SeBackupPrivilege",
    L"SeChangeNotifyPrivilege",
    L"SeCreateGlobalPrivilege",
    L"SeCreatePagefilePrivilege",
    L"SeCreatePermanentPrivilege",
    L"SeCreateSymbolicLinkPrivilege",
    L"SeCreateTokenPrivilege",
    L"SeDebugPrivilege",
    L"SeDelegateSessionUserImpersonatePrivilege",
    L"SeEnableDelegationPrivilege",
    L"SeImpersonatePrivilege",
    L"SeIncreaseBasePriorityPrivilege",
    L"SeIncreaseQuotaPrivilege",
    L"SeIncreaseWorkingSetPrivilege",
    L"SeLoadDriverPrivilege",
    L"SeLockMemoryPrivilege",
    L"SeMachineAccountPrivilege",
    L"SeManageVolumePrivilege",
    L"SeProfileSingleProcessPrivilege",
    L"SeRelabelPrivilege",
    L"SeRemoteShutdownPrivilege",
    L"SeRestorePrivilege",
    L"SeSecurityPrivilege",
    L"SeShutdownPrivilege",
    L"SeSyncAgentPrivilege",
    L"SeSystemEnvironmentPrivilege",
    L"SeSystemProfilePrivilege",
    L"SeSystemtimePrivilege",
    L"SeTakeOwnershipPrivilege",
    L"SeTcbPrivilege",
    L"SeTimeZonePrivilege",
    L"SeTrustedCredManAccessPrivilege",
    L"SeUndockPrivilege",
    L"SeUnsolicitedInputPrivilege",
};


///
/// Note: this is just a fake excuse to use assembly in VS, for real world use `NtCurrentTeb()`
///
EXTERN_C uptr GetTeb();
EXTERN_C usize GetTebLength();

#ifdef _WIN64
#define TEB_OFFSET 0x30
#define PEB_OFFSET 0x60
#else
#define TEB_OFFSET 0x18
#define PEB_OFFSET 0x30
#endif

namespace pwn::windows::process
{

Process::Memory::Memory() : Memory(nullptr)
{
}

Process::Memory::Memory(SharedHandle& h) : m_process_handle(h)
{
}

auto
Process::Memory::Read(uptr const Address, usize Length) -> Result<std::vector<u8>>
{
    auto out = std::vector<u8>(Length);
    size_t dwNbRead;
    if ( ::ReadProcessMemory(
             m_process_handle->get(),
             reinterpret_cast<LPVOID>(Address),
             out.data(),
             Length,
             &dwNbRead) == false )
    {
        log::perror(L"ReadProcessMemory()");
        return Err(ErrorCode::RuntimeError);
    }

    return Ok(out);
}

auto
Process::Memory::Memset(uptr const address, const size_t size, const u8 val) -> Result<usize>
{
    auto data = std::vector<u8>(size);
    std::fill(data.begin(), data.end(), val);
    return Write(address, data);
}

auto
Process::Memory::Write(uptr const Address, std::vector<u8> data) -> Result<usize>
{
    size_t dwNbWritten;
    if ( ::WriteProcessMemory(
             m_process_handle->get(),
             reinterpret_cast<LPVOID>(Address),
             data.data(),
             data.size(),
             &dwNbWritten) != false )
    {
        log::perror(L"WriteProcessMemory()");
        return Err(ErrorCode::RuntimeError);
    }

    return Ok(dwNbWritten);
}

auto
Process::Memory::allocate(const size_t Size, const wchar_t Permission[3], const uptr ForcedMappingAddress, bool wipe)
    -> Result<uptr>
{
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
        m_process_handle->get(),
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

auto
Process::Memory::free(const uptr Address) -> bool
{
    return ::VirtualFreeEx(m_process_handle->get(), reinterpret_cast<LPVOID>(Address), 0, MEM_RELEASE) == 0;
}


Process::Process() : Process(::GetCurrentProcessId(), false)
{
}

Process::Process(u32 pid, bool kill_on_delete) : m_Pid(pid), m_Peb(nullptr), m_Teb(nullptr), m_Privileges()
{
    m_IsSelf      = (m_Pid == ::GetCurrentProcessId());
    m_KillOnClose = m_IsSelf ? false : kill_on_delete;

    // Process PPID
    {
        auto ppid = pwn::windows::system::ppid(pid);
        m_Ppid    = ppid ? ppid.value() : -1;
    }

    // Full path
    {
        auto hProcess   = pwn::UniqueHandle {::OpenProcess(MAXIMUM_ALLOWED, false, m_Pid)};
        m_ProcessHandle = std::make_shared<UniqueHandle>(std::move(hProcess));
        Memory          = Memory::Memory(m_ProcessHandle);

        wchar_t exeName[MAX_PATH] = {0};
        DWORD size                = __countof(exeName);
        DWORD count               = ::QueryFullProcessImageName(m_ProcessHandle->get(), 0, exeName, &size);

        m_Path = std::wstring {exeName};
    }

    // Integrity
    if ( Failed(IntegrityLevel()) )
    {
        err(L"Failed to retrieve the integrity level");
    }
}

Process::~Process()
{
    if ( m_KillOnClose && !m_IsSelf )
    {
        Kill();
    }
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

fs::path const
Process::Path() const
{
    return fs::path {m_Path};
}

const HANDLE
Process::handle() const
{
    return m_ProcessHandle->get();
}

PPEB
Process::peb()
{
    if ( !m_Peb )
    {
        auto res = Memory.Read((uptr)(teb() + FIELD_OFFSET(TEB, ProcessEnvironmentBlock)), sizeof(uptr));
        if ( Success(res) )
        {
            auto val = Value(res);
            m_Peb    = (PPEB)val.data();
        }

        if ( !m_Peb )
        {
            throw std::runtime_error("PEB could not be set");
        }
    }
    return m_Peb;
}

PTEB
Process::teb()
{
    if(m_Teb)
    {
        return m_Teb;
    }

    if ( m_IsSelf )
    {
        //m_Teb = NtCurrentTeb();
        m_Teb = (uptr)GetTeb();
    }
    else
    {
        //
        // Copy the function from the local process to the remote
        //
        const uptr pfnGetTeb = &GetTeb;
        const usize GetTebFunctionLength = GetTebLength();
        const std::unique_ptr<u8> sc;
        sc.resize(GetTebFunctionLength);
        RtlCopyMemory(sc.get(), pfnGetTeb, GetTebFunctionLength);

        /*
            const std::vector<u8> sc = {
                // clang-format off
                0x48, 0x8d, 0x0d, 0x80, 0x00, 0x00, 0x00, // lea rcx, [rip+0x80]
                0x65, 0x48, 0xa1, 0x30, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // mov rax, gs:0x30
                0x48, 0x89, 0x01, // mov [rcx], rax
                0x48, 0x31, 0xc0, 0xfe, 0xc0, // xor rax, rax; inc al
                0xc3 // ret
                // clang-format on
            };
        */
        auto const ptr = Value(Memory.allocate(0x1000, L"rx"));
        Memory.Write(ptr, sc);

        //
        // Execute the remote thread
        //
        {
                DWORD ExitCode = 0;
                auto hProcess  = pwn::UniqueHandle {::CreateRemoteThreadEx(
                    m_ProcessHandle->get(),
                    nullptr,
                    0,
                    reinterpret_cast<LPTHREAD_START_ROUTINE>(ptr),
                    (ptr + 0x100),
                    0,
                    nullptr,
                    nullptr)};

                ::WaitForSingleObject(hProcess.get(), INFINITE);
                if ( ::GetExitCodeThread(hProcess.get(), &ExitCode) && ExitCode == 0 )
                {
                    auto res = Memory.Read(ptr + 0x100, sizeof(uptr));
                    if ( Success(res) )
                    {
                        m_Teb = ((PTEB)Value(res).data());
                    }
                }
        }

        Memory.free(ptr);
    }

    return m_Teb;
}


auto
Process::enumerate_privileges() -> bool
{
    auto hToken = pwn::UniqueHandle(
        [&]() -> HANDLE
        {
            HANDLE hProcessToken = nullptr;
            return (::OpenProcessToken(m_ProcessHandle->get(), TOKEN_QUERY, &hProcessToken)) ? hProcessToken : nullptr;
        }());

    if ( !hToken )
    {
        perror(L"OpenProcessToken()");
        return false;
    }

    DWORD dwReturnLength = 0;
    std::unique_ptr<TOKEN_PRIVILEGES[]> TokenPrivs;

    do
    {
        const DWORD cursz = dwReturnLength;
        TokenPrivs        = std::make_unique<TOKEN_PRIVILEGES[]>(cursz);

        if ( ::GetTokenInformation(hToken.get(), TokenPrivileges, TokenPrivs.get(), cursz, &dwReturnLength) )
        {
            break;
        }

        if ( ::GetLastError() == ERROR_INSUFFICIENT_BUFFER )
        {
            continue;
        }

        perror(L"GetTokenInformation()");
        return false;

    } while ( true );

    info(L"got {} privs", TokenPrivs.get()->PrivilegeCount);

    return true;
}

auto
Process::is_elevated() -> bool
{
    auto hToken = pwn::UniqueHandle(
        [&]() -> HANDLE
        {
            HANDLE h = nullptr;
            return ( ::OpenProcessToken(m_ProcessHandle->get(), TOKEN_QUERY, &h) ) ? h : nullptr;
        }());

    if ( !hToken )
    {
        log::perror(L"OpenProcessToken()");
        return false;
    }

    TOKEN_ELEVATION TokenInfo = {0};
    DWORD dwReturnLength      = 0;

    if ( ::GetTokenInformation(hToken.get(), TokenElevation, &TokenInfo, sizeof(TOKEN_ELEVATION), &dwReturnLength) )
    {
        return TokenInfo.TokenIsElevated;
    }

    log::perror(L"GetTokenInformation()");
    return false;
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
    auto hProcess = pwn::UniqueHandle {::OpenProcess(PROCESS_TERMINATE, false, m_Pid)};
    if ( !hProcess )
    {
        pwn::log::perror(L"OpenProcess() failed");
        return Err(ErrorCode::ExternalApiCallFailed);
    }

    dbg(L"attempting to kill {} (pid={})", hProcess.get(), m_Pid);
    bool bRes = (::TerminateProcess(hProcess.get(), EXIT_FAILURE) == TRUE);
    return Ok(bRes);
}


auto
Processes() -> std::vector<std::tuple<std::wstring, u32>>
{
    u16 maxCount = 256;
    std::unique_ptr<DWORD[]> pids;
    int count = 0;
    std::vector<std::tuple<std::wstring, u32>> processes;

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
        u32 pid       = pids[i];
        auto hProcess = pwn::UniqueHandle {::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid)};
        if ( !hProcess )
        {
            continue;
        }

        WCHAR exeName[MAX_PATH] = {0};
        DWORD size              = __countof(exeName);
        DWORD count             = ::QueryFullProcessImageName(hProcess.get(), 0, exeName, &size);

        processes.emplace_back(exeName, pid);
    }

    return processes;
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

    pwn::UniqueHandle hProcessToken;
    {
        HANDLE h;
        hProcessToken = pwn::UniqueHandle {
            (::OpenProcessToken(hProcessHandle.get(), TOKEN_ADJUST_PRIVILEGES, &h) == TRUE) ? h : nullptr};
    }
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


Result<bool>
Process::AddPrivilege(std::wstring const& PrivilegeName)
{
    auto hProcess = pwn::UniqueHandle {::OpenProcess(PROCESS_QUERY_INFORMATION, 0, m_Pid)};
    if ( !hProcess )
    {
        return Err(ErrorCode::GenericError);
    }

    pwn::UniqueHandle hToken;
    {
        HANDLE h;
        hToken =
            pwn::UniqueHandle {(::OpenProcessToken(hProcess.get(), TOKEN_ADJUST_PRIVILEGES, &h) == TRUE) ? h : nullptr};
    }

    LUID Luid = {0};

    if ( ::LookupPrivilegeValueW(nullptr, PrivilegeName.c_str(), &Luid) == false )
    {
        return Err(ErrorCode::GenericError);
    }

    size_t nBufferSize                 = sizeof(TOKEN_PRIVILEGES) + 1 * sizeof(LUID_AND_ATTRIBUTES);
    auto buffer                        = std::make_unique<u8[]>(nBufferSize);
    auto NewState                      = (PTOKEN_PRIVILEGES)buffer.get();
    NewState->PrivilegeCount           = 1;
    NewState->Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    NewState->Privileges[0].Luid       = Luid;

    if ( ::AdjustTokenPrivileges(hToken.get(), FALSE, NewState, 0, (PTOKEN_PRIVILEGES) nullptr, (PDWORD) nullptr) ==
         FALSE )
    {
        if ( ::GetLastError() == ERROR_NOT_ALL_ASSIGNED )
        {
            return Err(ErrorCode::PartialResult);
        }

        return Err(ErrorCode::ExternalApiCallFailed);
    }

    return Ok(true);
}


Result<bool>
Process::HasPrivilege(std::wstring const& PrivilegeName)
{
    LUID Luid = {0};

    auto hProcess = pwn::UniqueHandle {::OpenProcess(PROCESS_QUERY_INFORMATION, 0, m_Pid)};
    if ( !hProcess )
    {
        return Err(ErrorCode::GenericError);
    }


    dbg(L"Checking for '{}' for PID=%d...\n", PrivilegeName.c_str(), m_Pid);

    if ( ::LookupPrivilegeValueW(nullptr, PrivilegeName.c_str(), &Luid) == false )
    {
        log::perror(L"LookupPrivilegeValue");
        return Err(ErrorCode::ExternalApiCallFailed);
    }

    LUID_AND_ATTRIBUTES PrivAttr = {{0}};
    PrivAttr.Luid                = Luid;
    PrivAttr.Attributes          = SE_PRIVILEGE_ENABLED | SE_PRIVILEGE_ENABLED_BY_DEFAULT;

    PRIVILEGE_SET PrivSet  = {0};
    PrivSet.PrivilegeCount = 1;
    PrivSet.Privilege[0]   = PrivAttr;

    pwn::UniqueHandle hToken;
    {
        HANDLE h;
        hToken =
            pwn::UniqueHandle {(::OpenProcessToken(hProcess.get(), TOKEN_ADJUST_PRIVILEGES, &h) == TRUE) ? h : nullptr};
    }
    if ( !hToken )
    {
        return Err(ErrorCode::GenericError);
    }

    BOOL bHasPriv;
    if ( ::PrivilegeCheck(hToken.get(), &PrivSet, &bHasPriv) == FALSE )
    {
        log::perror(L"LookupPrivilegeValue");
        return Err(ErrorCode::ExternalApiCallFailed);
    }

    return Ok(bHasPriv == TRUE);
}


auto
execv(const std::wstring_view& CommandLine, const u32 ParentPid) -> Result<std::tuple<HANDLE, HANDLE>>
{
    std::unique_ptr<u8[]> AttributeList;
    pwn::UniqueHandle hParentProcess;
    STARTUPINFOEX si = {
        {0},
    };
    PROCESS_INFORMATION pi = {0};
    const u32 dwFlags = EXTENDED_STARTUPINFO_PRESENT | CREATE_NEW_CONSOLE;
    si.StartupInfo.cb = sizeof(STARTUPINFOEX);

    if ( ParentPid )
    {
        HANDLE hProcess = ::OpenProcess(PROCESS_CREATE_PROCESS, false, ParentPid);
        if ( hProcess )
        {
            size_t AttrListSize = 0;
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
            perror(L"OpenProcess()");
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
             &pi) == 0 )
    {
        perror(L"CreateProcess()");
        return Err(ErrorCode::RuntimeError);
    }

    if ( ParentPid )
    {
        if ( si.lpAttributeList != nullptr )
        {
            ::DeleteProcThreadAttributeList(si.lpAttributeList);
        }
    }

    dbg(L"'{}' spawned with PID {}", CommandLine, pi.dwProcessId);
    return Ok(std::make_tuple(pi.hProcess, pi.hThread));
}


_Success_(return )
auto
system(_In_ const std::wstring& CommandLine, _In_ const std::wstring& Operation) -> bool
{
    auto args = pwn::utils::split(CommandLine, L' ');
    auto cmd {args[0]};
    args.erase(args.begin());
    auto params = pwn::utils::join(args);

    return static_cast<bool>(
        reinterpret_cast<long long>(
            ::ShellExecuteW(nullptr, Operation.c_str(), cmd.c_str(), params.c_str(), nullptr, SW_SHOW)) > 32);
}


_Success_(return != nullptr)
auto
cmd() -> HANDLE
{
    auto res = execv(L"cmd.exe");
    if ( Success(res) )
    {
        return std::get<0>(Value(res));
    }
    return INVALID_HANDLE_VALUE;
}


appcontainer::AppContainer::AppContainer(
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

    dbg(L"sid={}\n", m_SidAsString.c_str());

    //
    // Get the folder path
    //
    PWSTR path;
    if ( SUCCEEDED(::GetAppContainerFolderPath(m_SidAsString.c_str(), &path)) )
    {
        m_FolderPath = path;
        ::CoTaskMemFree(path);
    }

    dbg(L"folder_path={}\n", m_FolderPath.c_str());


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
    size_t size = 0;
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


appcontainer::AppContainer::~AppContainer()
{
    dbg(L"freeing container '{}'\n", m_SidAsString.c_str());

    if ( m_SecurityCapabilities.CapabilityCount != 0u )
    {
        for ( u32 i = 0; i < m_SecurityCapabilities.CapabilityCount; i++ )
        {
            delete[] m_SecurityCapabilities.Capabilities[i].Sid;
        }
        delete[](u8*) m_SecurityCapabilities.Capabilities;
    }

    if ( m_StartupInfo.lpAttributeList != nullptr )
    {
        delete[](u8*) m_StartupInfo.lpAttributeList;
    }

    if ( m_AppContainerSid != nullptr )
    {
        ::FreeSid(m_AppContainerSid);
    }
}


_Success_(return )
auto
appcontainer::AppContainer::allow_file_or_directory(_In_ const std::wstring& file_or_directory_name) -> bool
{
    return set_named_object_access(file_or_directory_name, SE_FILE_OBJECT, GRANT_ACCESS, FILE_ALL_ACCESS);
}


_Success_(return )
auto
appcontainer::AppContainer::allow_registry_key(_In_ const std::wstring& regkey) -> bool
{
    return set_named_object_access(regkey, SE_REGISTRY_KEY, GRANT_ACCESS, FILE_ALL_ACCESS);
}


_Success_(return )
auto
appcontainer::AppContainer::spawn() -> bool
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


_Success_(return )
auto
appcontainer::AppContainer::set_named_object_access(
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


_Success_(return )
auto
appcontainer::AppContainer::join(_In_ const u32 dwTimeout) -> bool
{
    return ::WaitForSingleObject(m_ProcessInfo.hProcess, dwTimeout) != WAIT_OBJECT_0;
}


_Success_(return )
auto
appcontainer::AppContainer::restore_acls() -> bool
{
    bool bRes = TRUE;

    for ( auto& acl : m_OriginalAcls )
    {
        auto const& ObjectName = std::get<0>(acl);
        auto const& ObjectType = std::get<1>(acl);
        auto const& pOldAcl    = std::get<2>(acl);
        dbg(L"restoring original acl for '{}'\n", ObjectName.c_str());
        bRes &= static_cast<int>(
            ::SetNamedSecurityInfo(
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


} // namespace pwn::windows::process
