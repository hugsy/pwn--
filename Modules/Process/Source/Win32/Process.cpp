#include "Win32/Process.hpp"

#include <accctrl.h>
#include <aclapi.h>
#include <psapi.h>
#include <sddl.h>
#include <shellapi.h>
#include <tlhelp32.h>
#include <userenv.h>

#include "Handle.hpp"
#include "Log.hpp"
#include "Utils.hpp"
#include "Win32/API.hpp"
#include "Win32/System.hpp"
#include "Win32/Thread.hpp"

using namespace pwn;

#define xdbg(...) dbg("[Process::Process] " __VA_ARGS__)

EXTERN_C_START
bool
GetPeb(uptr* peb);

usize
GetPebLength();
EXTERN_C_END


namespace pwn::Process
{

std::string const
ProcessAccessToString(u32 ProcessAccess)
{
    std::ostringstream str;
    u32 found {0};

#define CheckAccessAndAppend(x)                                                                                        \
    {                                                                                                                  \
        if ( (ProcessAccess & x) == x )                                                                                \
        {                                                                                                              \
            if ( !str.str().empty() )                                                                                  \
                str << ", ";                                                                                           \
            str << #x;                                                                                                 \
            found += x;                                                                                                \
        }                                                                                                              \
    }
    CheckAccessAndAppend(PROCESS_ALL_ACCESS);
    CheckAccessAndAppend(PROCESS_TERMINATE);
    CheckAccessAndAppend(PROCESS_CREATE_THREAD);
    CheckAccessAndAppend(PROCESS_SET_SESSIONID);
    CheckAccessAndAppend(PROCESS_VM_OPERATION);
    CheckAccessAndAppend(PROCESS_VM_READ);
    CheckAccessAndAppend(PROCESS_VM_WRITE);
    CheckAccessAndAppend(PROCESS_DUP_HANDLE);
    CheckAccessAndAppend(PROCESS_CREATE_PROCESS);
    CheckAccessAndAppend(PROCESS_SET_QUOTA);
    CheckAccessAndAppend(PROCESS_SET_INFORMATION);
    CheckAccessAndAppend(PROCESS_QUERY_INFORMATION);
    CheckAccessAndAppend(PROCESS_SUSPEND_RESUME);
    CheckAccessAndAppend(PROCESS_QUERY_LIMITED_INFORMATION);
    CheckAccessAndAppend(PROCESS_SET_LIMITED_INFORMATION);
#undef CheckAccessAndAppend

    if ( found != ProcessAccess )
    {
        if ( !str.str().empty() )
            str << ", ";
        str << std::hex << (ProcessAccess - found);
    }

    return str.str();
}


#pragma region Process

Process::Process(u32 Pid) : m_ProcessId {Pid}
{
    if ( !m_ProcessId )
    {
        throw std::runtime_error("Process initialization error");
    }

    //
    // Gather a minimum set of information about the process for performance. Extra information will be
    // lazily fetched
    //
    if ( Failed(ReOpenProcessWith(PROCESS_QUERY_INFORMATION)) &&
         Failed(ReOpenProcessWith(PROCESS_QUERY_LIMITED_INFORMATION)) )
    {
        throw std::runtime_error("Process initialization error");
    }

    // Process PPID
    {
        auto BasicInfo    = Value(Query<PROCESS_BASIC_INFORMATION>(PROCESSINFOCLASS::ProcessBasicInformation));
        m_ParentProcessId = HandleToULong(BasicInfo->InheritedFromUniqueProcessId);
    }


    // Full path
    {
        auto NativeFilePath = Value(Query<UNICODE_STRING>(PROCESSINFOCLASS::ProcessImageFileName));
        m_NativePath        = (NativeFilePath->Length) ? std::wstring {NativeFilePath->Buffer} : std::wstring {L""};
    }
}


Process::Process(HANDLE&& hProcess) : Process(::GetProcessId(hProcess))
{
    m_ProcessHandle.reset(std::move(hProcess));
    // TODO: fix by querying existing access
    m_ProcessHandleAccessMask = PROCESS_QUERY_LIMITED_INFORMATION;
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
    if ( !IsRemote() )
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
        auto res = Query<PROCESS_BASIC_INFORMATION>(PROCESSINFOCLASS::ProcessBasicInformation);
        if ( Failed(res) )
        {
            err("Failed to query process information");
            return nullptr;
        }

        const auto info = Value(std::move(res));
        m_Peb           = info->PebBaseAddress;
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
    Memory ProcessMemory(*this);

    auto res = ProcessMemory.Allocate(AllocationSize, L"rwx");
    if ( Failed(res) )
    {
        return Err(Error::AllocationError);
    }

    auto const Target = Value(res);
    ProcessMemory.Memset(Target, AllocationSize);
    ProcessMemory.Write(Target, sc);

    //
    // Execute it
    //
    {
        DWORD ExitCode = 0;
        auto hThread   = UniqueHandle {::CreateRemoteThreadEx(
            m_ProcessHandle.get(),
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
            auto res2 = ProcessMemory.Read(Target + CodePointerSize, sizeof(uptr));
            if ( Success(res2) )
            {
                Result = (*(uptr*)(Value(res2).data()));
            }
        }
    }
    ProcessMemory.Free(Target);

    return Ok(Result);
}


std::wostream&
operator<<(std::wostream& wos, const Integrity i)
{
    switch ( i )
    {
    case Integrity::Low:
        wos << L"INTEGRITY_LOW";
        break;

    case Integrity::Medium:
        wos << L"INTEGRITY_MEDIUM";
        break;

    case Integrity::High:
        wos << L"INTEGRITY_HIGH";
        break;

    case Integrity::System:
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
    if ( Failed(ReOpenProcessWith(PROCESS_TERMINATE)) )
    {
        return Err(Error::PermissionDenied);
    }

    dbg(L"Attempting to kill PID={})", m_ProcessId);
    bool bRes = (::TerminateProcess(m_ProcessHandle.get(), EXIT_FAILURE) == TRUE);
    if ( !bRes )
    {
        Log::perror(L"TerminateProcess()");
        return Err(Error::ExternalApiCallFailed);
    }

    return Ok(bRes);
}


Result<std::vector<u32>>
Processes()
{
    return System::Threads().and_then(
        [](auto&& pids) -> Result<std::vector<u32>>
        {
            return Ok(std::move(std::views::keys(pids) | std::ranges::to<std::vector>()));
        });
}


Result<Integrity>
Process::IntegrityLevel()
{
    //
    // Check from the cache
    //
    if ( m_IntegrityLevel != Integrity::Unknown )
    {
        return Ok(m_IntegrityLevel);
    }

    //
    // Otherwise try to determine it
    //
    auto hProcessHandle = UniqueHandle {::OpenProcess(PROCESS_QUERY_INFORMATION, false, m_ProcessId)};
    if ( !hProcessHandle )
    {
        return Err(Error::InvalidProcess);
    }

    auto hProcessToken = UniqueHandle(
        [&]() -> HANDLE
        {
            HANDLE h;
            return (::OpenProcessToken(hProcessHandle.get(), TOKEN_ADJUST_PRIVILEGES, &h) == TRUE) ? h : nullptr;
        }());
    if ( !hProcessToken )
    {
        return Err(Error::PermissionDenied);
    }

    DWORD dwLengthNeeded = 0;
    if ( (::GetTokenInformation(hProcessToken.get(), TokenIntegrityLevel, nullptr, 0, &dwLengthNeeded) == false) ||
         (::GetLastError() != ERROR_INSUFFICIENT_BUFFER) )
    {
        return Err(Error::ExternalApiCallFailed);
    }

    auto pTokenBuffer = std::make_unique<TOKEN_MANDATORY_LABEL[]>(dwLengthNeeded);
    if ( ::GetTokenInformation(
             hProcessToken.get(),
             TokenIntegrityLevel,
             pTokenBuffer.get(),
             dwLengthNeeded,
             &dwLengthNeeded) == false )
    {
        return Err(Error::ExternalApiCallFailed);
    }

    const u32 dwIntegrityLevel = *::GetSidSubAuthority(
        pTokenBuffer.get()->Label.Sid,
        (u32)(UCHAR)(*::GetSidSubAuthorityCount(pTokenBuffer.get()->Label.Sid) - 1));

    if ( dwIntegrityLevel == SECURITY_MANDATORY_LOW_RID )
    {
        m_IntegrityLevel = Integrity::Low;
    }
    else if ( SECURITY_MANDATORY_MEDIUM_RID <= dwIntegrityLevel && dwIntegrityLevel < SECURITY_MANDATORY_HIGH_RID )
    {
        m_IntegrityLevel = Integrity::Medium;
    }
    else if ( dwIntegrityLevel == SECURITY_MANDATORY_HIGH_RID )
    {
        m_IntegrityLevel = Integrity::High;
    }
    else if ( dwIntegrityLevel == SECURITY_MANDATORY_SYSTEM_RID )
    {
        m_IntegrityLevel = Integrity::System;
    }

    return Ok(m_IntegrityLevel);
}


std::vector<u32>
Process::Threads() const
{
    u32 const CurrentPid = m_ProcessId;

    auto res = pwn::System::Threads();
    if ( Failed(res) )
    {
        return {};
    }

    auto const SystemThreadIds = Value(res);
    auto IsCurrentProcess      = [CurrentPid](auto const& x)
    {
        return std::get<0>(x) == CurrentPid;
    };

    std::vector<u32> CurrentProcessThreads;
    for ( auto const [pid, tid] : SystemThreadIds | std::views::filter(IsCurrentProcess) )
    {
        CurrentProcessThreads.push_back(tid);
    }
    return CurrentProcessThreads;
};

Result<pwn::Process::Thread>
Process::Thread(usize tid) const
{
    const auto threads = this->Threads();
    const auto it      = std::find(threads.cbegin(), threads.cend(), tid);
    if ( it == threads.cend() )
    {
        return Err(Error::NotFound);
    }

    return Ok(std::move(pwn::Process::Thread(tid)));
}


pwn::Process::Process
Current()
{
    return Process(::GetCurrentProcessId());
}


/*
Result<Process>
Process::New(const std::wstring_view& CommandLine, const u32 ParentPid)
{
    std::unique_ptr<u8[]> AttributeList;
    UniqueHandle hParentProcess;
    STARTUPINFOEX si {};
    PROCESS_INFORMATION pi {};
    const u32 dwFlags = EXTENDED_STARTUPINFO_PRESENT | CREATE_NEW_CONSOLE;
    si.StartupInfo.cb = sizeof(STARTUPINFOEX);

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

            hParentProcess = UniqueHandle {hProcess};
        }
        else
        {
            Log::perror(L"OpenProcess()");
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
        Log::perror(L"CreateProcess()");
        return Err(Error::RuntimeError);
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
        return Err(Error::AllocationError);
    }
    return Ok(std::move(p));
}
*/


Result<bool>
Process::ReOpenProcessWith(const DWORD DesiredAccess)
{

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
    HANDLE hProcess   = ::OpenProcess(NewAccessMask, false, m_ProcessId);
    if ( hProcess == nullptr )
    {
        Log::perror(L"OpenProcess()");
        return Err(Error::PermissionDenied);
    }

    //
    // Affect the unique pointer (releasing - and closing - the old one if existing) and update the mask
    //
    m_ProcessHandle           = UniqueHandle {hProcess};
    m_ProcessHandleAccessMask = NewAccessMask;

    xdbg("Process handle with {}", ProcessAccessToString(m_ProcessHandleAccessMask).c_str());
    return Ok(true);
}


Result<std::unique_ptr<u8[]>>
Process::QueryInternal(const PROCESSINFOCLASS ProcessInformationClass, const usize InitialSize)
{
    usize Size = InitialSize;

    auto Buffer = std::make_unique<u8[]>(Size);
    if ( !Buffer )
    {
        return Err(Error::AllocationError);
    }

    do
    {
        ::memset(Buffer.get(), 0, Size);

        ULONG ReturnLength = 0;
        NTSTATUS Status    = m_IsWow64 ? Resolver::ntdll::NtWow64QueryInformationProcess64(
                                          m_ProcessHandle.get(),
                                          ProcessInformationClass,
                                          Buffer.get(),
                                          Size,
                                          &ReturnLength) :
                                         Resolver::ntdll::NtQueryInformationProcess(
                                          m_ProcessHandle.get(),
                                          ProcessInformationClass,
                                          Buffer.get(),
                                          Size,
                                          &ReturnLength);
        if ( NT_SUCCESS(Status) )
        {
            break;
        }


        switch ( Status )
        {
        case STATUS_INFO_LENGTH_MISMATCH:
        case STATUS_BUFFER_TOO_SMALL:
        {
            Size   = ReturnLength;
            Buffer = std::make_unique<u8[]>(Size);
            continue;
        }
        default:
            break;
        }

        Log::ntperror(L"NtQueryInformationProcess()", Status);
        return Err(Error::PermissionDenied);

    } while ( true );

    return Ok(std::move(Buffer));
}

#pragma endregion Process


// Result<bool>
// Process::System(_In_ const std::wstring& CommandLine, _In_ const std::wstring& Operation)
// {
//     auto args = Utils::StringLib::Split(CommandLine, L' ');
//     auto cmd {args[0]};
//     args.erase(args.begin());
//     auto params  = Utils::StringLib::Join(args, L' ');
//     bool success = static_cast<bool>(
//         reinterpret_cast<long long>(
//             ::ShellExecuteW(nullptr, Operation.c_str(), cmd.c_str(), params.c_str(), nullptr, SW_SHOW)) > 32);
//     return Ok(success);
// }


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
    m_SidAsString = [&]()
    {
        std::wstring sid;
        PWSTR str;
        if ( ::ConvertSidToStringSidW(m_AppContainerSid, &str) )
        {
            sid = str;
            ::LocalFree(str);
        }
        return sid;
    }();
    if ( m_SidAsString.empty() )
    {
        throw std::runtime_error("Failed to get SID");
    }


    dbg(L"sid={}", m_SidAsString.c_str());

    //
    // Get the folder path
    //
    m_FolderPath = [&]()
    {
        std::wstring str;
        PWSTR path;
        if ( SUCCEEDED(::GetAppContainerFolderPath(m_SidAsString.c_str(), &path)) )
        {
            str = path;
            ::CoTaskMemFree(path);
        }
        return str;
    }();
    if ( m_FolderPath.empty() )
    {
        throw std::runtime_error("Failed to determine folder path");
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
    ::InitializeProcThreadAttributeList(nullptr, 1, 0, (PSIZE_T)&size);
    if ( size == 0u )
    {
        throw std::runtime_error("InitializeProcThreadAttributeList() failed");
    }

    m_StartupInfo.StartupInfo.cb  = sizeof(STARTUPINFOEX);
    m_StartupInfo.lpAttributeList = (LPPROC_THREAD_ATTRIBUTE_LIST)::new u8[size];

    if ( ::InitializeProcThreadAttributeList(m_StartupInfo.lpAttributeList, 1, 0, (PSIZE_T)&size) == 0 )
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


auto
AppContainer::AllowFileOrDirectory(_In_ const std::wstring& file_or_directory_name) -> bool
{
    return SetNamedObjectAccess(file_or_directory_name, SE_FILE_OBJECT, GRANT_ACCESS, FILE_ALL_ACCESS);
}


auto
AppContainer::AllowRegistryKey(_In_ const std::wstring& regkey) -> bool
{
    return SetNamedObjectAccess(regkey, SE_REGISTRY_KEY, GRANT_ACCESS, FILE_ALL_ACCESS);
}


auto
AppContainer::Spawn() -> bool
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


auto
AppContainer::SetNamedObjectAccess(
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


auto
AppContainer::Join(_In_ const u32 dwTimeout) -> bool
{
    return ::WaitForSingleObject(m_ProcessInfo.hProcess, dwTimeout) != WAIT_OBJECT_0;
}


auto
AppContainer::RestoreAcls() -> bool
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

} // namespace pwn::Process


template<>
struct std::formatter<Process::Integrity, wchar_t> : std::formatter<std::wstring, wchar_t>
{
    auto
    format(Process::Integrity i, ::std::wformat_context& ctx)
    {
        const ::std::wstring wstr = [&i]()
        {
            switch ( i )
            {
            case Process::Integrity::Low:
                return L"INTEGRITY_LOW";
            case Process::Integrity::Medium:
                return L"INTEGRITY_MEDIUM";
            case Process::Integrity::High:
                return L"INTEGRITY_HIGH";
            case Process::Integrity::System:
                return L"INTEGRITY_SYSTEM";
            default:
                return L"INTEGRITY_UNKNOWN";
            }
        }();
        return std::formatter<std::wstring, wchar_t>::format(wstr, ctx);
    }
};


template<>
struct std::formatter<Process::Process, wchar_t> : std::formatter<std::wstring, wchar_t>
{
    auto
    format(Process::Process const& p, ::std::wformat_context& ctx)
    {
        ::std::wstring wstr;
        return std::formatter<std::wstring, wchar_t>::format(wstr, ctx);
    }
};
