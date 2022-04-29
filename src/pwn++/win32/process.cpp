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


///
/// Note: this is just a fake excuse to use assembly in VS, for real world use `NtCurrentTeb()`
///
#ifdef _WIN64
#define TEB_OFFSET 0x30
#define PEB_OFFSET 0x60
extern "C" auto
x64_get_teb() -> uptr;
#define get_teb x64_get_teb
#else
#define TEB_OFFSET 0x18
#define PEB_OFFSET 0x30
extern "C" uptr
x86_get_teb();
#define get_teb x86_get_teb
#endif


namespace pwn::win::process
{


Process::Process(u32 pid) : m_pid(pid)
{
    // Process PPID
    {
        auto ppid = pwn::win::system::ppid(pid);
        if ( !ppid )
            throw std::runtime_error("could not read ppid");
        m_ppid = ppid.value();
    }

    // Full path
    {
        hProcess = ::OpenProcess(MAXIMUM_ALLOWED, false, pid);
        if ( !hProcess )
        {
            throw std::runtime_error("could not OpenProcess(MAXIMUM_ALLOWED)");
        }

        wchar_t exeName[MAX_PATH] = {0};
        DWORD size                = __countof(exeName);
        DWORD count               = ::QueryFullProcessImageName(hProcess.get(), 0, exeName, &size);

        m_path = std::wstring {exeName};
    }

    // Integrity
    {
        m_integrity_level = get_integrity_level(pid);
    }
}

u32 const
Process::ppid() const
{
    return m_ppid;
}

u32 const
Process::pid() const
{
    return m_pid;
}

fs::path const
Process::path() const
{
    return fs::path {m_path};
}

Process::Integrity const
Process::integrity() const
{
    return m_integrity_level;
}


auto
pid() -> u32
{
    return ::GetCurrentProcessId();
}


auto
ppid() -> std::optional<u32>
{
    return pwn::win::system::ppid(pid());
}


auto
list() -> std::vector<std::tuple<std::wstring, u32>>
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
        u32 pid = pids[i];
        pwn::utils::GenericHandle hProcess(::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid));
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


auto
get_integrity_level(const u32 pid = -1) -> Process::Integrity
{
    auto IntegrityLevel  = Process::Integrity::Unknown;
    u32 dwRes            = ERROR_SUCCESS;
    u32 dwIntegrityLevel = SECURITY_MANDATORY_MEDIUM_RID;
    DWORD dwProcessId    = (pid == -1) ? ::GetCurrentProcessId() : pid;

    do
    {
        auto hProcessHandle = pwn::utils::GenericHandle(::OpenProcess(PROCESS_QUERY_INFORMATION, false, dwProcessId));
        if ( !hProcessHandle )
        {
            dwRes = ::GetLastError();
            break;
        }

        HANDLE hToken;
        if ( ::OpenProcessToken(hProcessHandle.get(), TOKEN_QUERY, &hToken) == 0 )
        {
            dwRes = ::GetLastError();
            break;
        }

        auto hProcessToken = pwn::utils::GenericHandle(hToken);

        DWORD dwLengthNeeded = 0;

        if ( ::GetTokenInformation(hProcessToken.get(), TokenIntegrityLevel, nullptr, 0, &dwLengthNeeded) == 0 )
        {
            dwRes = ::GetLastError();
            if ( dwRes != ERROR_INSUFFICIENT_BUFFER )
            {
                dwRes = ::GetLastError();
                break;
            }
        }

        auto pTokenBuffer = std::make_unique<TOKEN_MANDATORY_LABEL[]>(dwLengthNeeded);

        if ( ::GetTokenInformation(
                 hProcessToken.get(),
                 TokenIntegrityLevel,
                 pTokenBuffer.get(),
                 dwLengthNeeded,
                 &dwLengthNeeded) == 0 )
        {
            dwRes = ::GetLastError();
            if ( dwRes != ERROR_INSUFFICIENT_BUFFER )
            {
                dwRes = ::GetLastError();
                break;
            }
        }


        dwIntegrityLevel = *::GetSidSubAuthority(
            pTokenBuffer.get()->Label.Sid,
            (u32)(UCHAR)(*::GetSidSubAuthorityCount(pTokenBuffer.get()->Label.Sid) - 1));

        if ( dwIntegrityLevel == SECURITY_MANDATORY_LOW_RID )
        {
            IntegrityLevel = Process::Integrity::Low;
        }
        else if ( SECURITY_MANDATORY_MEDIUM_RID < dwIntegrityLevel && dwIntegrityLevel < SECURITY_MANDATORY_HIGH_RID )
        {
            IntegrityLevel = Process::Integrity::Medium;
        }
        else if ( dwIntegrityLevel >= SECURITY_MANDATORY_HIGH_RID )
        {
            IntegrityLevel = Process::Integrity::High;
        }
        else if ( dwIntegrityLevel >= SECURITY_MANDATORY_SYSTEM_RID )
        {
            IntegrityLevel = Process::Integrity::System;
        }

        dwRes = ERROR_SUCCESS;

    } while ( 0 );

    return IntegrityLevel;
}


_Success_(return )
auto
execv(_In_ const wchar_t* lpCommandLine, _In_ u32 dwParentPid, _Out_ LPHANDLE lpNewProcessHandle) -> bool
{
    HANDLE hParentProcess = nullptr;
    STARTUPINFOEX si      = {
             {0},
    };
    PROCESS_INFORMATION pi = {
        nullptr,
    };
    u32 dwFlags       = EXTENDED_STARTUPINFO_PRESENT | CREATE_NEW_CONSOLE;
    si.StartupInfo.cb = sizeof(STARTUPINFOEX);

    size_t cmd_len = ::wcslen(lpCommandLine);

    auto cmd = std::make_unique<WCHAR[]>(cmd_len + 1);
    ::RtlCopyMemory(cmd.get(), lpCommandLine, 2 * cmd_len);

    if ( dwParentPid != 0u )
    {
        hParentProcess = ::OpenProcess(PROCESS_CREATE_PROCESS, FALSE, dwParentPid);
        if ( hParentProcess != nullptr )
        {
            size_t AttrListSize = 0;
            ::InitializeProcThreadAttributeList(nullptr, 1, 0, &AttrListSize);
            si.lpAttributeList = (LPPROC_THREAD_ATTRIBUTE_LIST)::HeapAlloc(::GetProcessHeap(), 0, AttrListSize);
            if ( si.lpAttributeList != nullptr )
            {
                ::InitializeProcThreadAttributeList(si.lpAttributeList, 1, 0, &AttrListSize);
                ::UpdateProcThreadAttribute(
                    si.lpAttributeList,
                    0,
                    PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,
                    &hParentProcess,
                    sizeof(HANDLE),
                    nullptr,
                    nullptr);
                dbg(L"Spawning '{}' with PPID=%d...\n", cmd.get(), dwParentPid);
            }
        }
        else
        {
            perror(L"OpenProcess()");
        }
    }
    else
    {
        dbg(L"Spawning '{}'...\n", cmd.get());
    }

    if ( ::CreateProcess(nullptr, cmd.get(), nullptr, nullptr, 1, dwFlags, nullptr, nullptr, (LPSTARTUPINFO)&si, &pi) ==
         0 )
    {
        perror(L"CreateProcess()");
        return FALSE;
    }

    ::CloseHandle(pi.hThread);
    if ( dwParentPid != 0u )
    {
        if ( si.lpAttributeList != nullptr )
        {
            ::DeleteProcThreadAttributeList(si.lpAttributeList);
            ::HeapFree(::GetProcessHeap(), 0, si.lpAttributeList);
        }

        if ( hParentProcess != nullptr )
        {
            ::CloseHandle(hParentProcess);
        }
    }

    dbg(L"'{}' spawned with PID %d\n", lpCommandLine, pi.dwProcessId);
    if ( lpNewProcessHandle != nullptr )
    {
        *lpNewProcessHandle = pi.hProcess;
    }
    else
    {
        ::CloseHandle(pi.hProcess);
    }

    return TRUE;
}


auto
execv(_In_ const wchar_t* lpCommandLine, _In_ u32 dwParentPid) -> std::optional<HANDLE>
{
    HANDLE hProcess = INVALID_HANDLE_VALUE;
    if ( execv(lpCommandLine, dwParentPid, &hProcess) != 0 )
    {
        return hProcess;
    }
    return std::nullopt;
}


_Success_(return )
auto
system(_In_ const std::wstring& lpCommandLine, _In_ const std::wstring& operation) -> bool
{
    auto args = pwn::utils::split(lpCommandLine, L' ');
    auto cmd {args[0]};
    args.erase(args.begin());
    auto params = pwn::utils::join(args);

    return static_cast<bool>(
        reinterpret_cast<long long>(
            ::ShellExecuteW(nullptr, operation.c_str(), cmd.c_str(), params.c_str(), nullptr, SW_SHOW)) > 32);
}


_Success_(return )
auto
kill(_In_ u32 dwProcessPid) -> bool
{
    HANDLE hProcess = ::OpenProcess(PROCESS_TERMINATE, FALSE, dwProcessPid);
    if ( hProcess == nullptr )
    {
        return FALSE;
    }
    return kill(hProcess);
}


_Success_(return )
auto
kill(_In_ HANDLE hProcess) -> bool
{
    dbg(L"attempting to kill %u (pid=%u)\n", hProcess, ::GetProcessId(hProcess));
    bool res = ::TerminateProcess(hProcess, EXIT_FAILURE);
    ::CloseHandle(hProcess);
    return res;
}


_Success_(return != nullptr)
auto
cmd() -> HANDLE
{
    auto hProcess = execv(L"cmd.exe");
    return hProcess ? hProcess.value() : INVALID_HANDLE_VALUE;
}


/*++

Get the TEB address of the current process

--*/
auto
teb() -> PTEB
{
    return NtCurrentTeb();
}


/*++

Get the PEB address of the current process

--*/
auto
peb() -> PPEB
{
    return teb()->ProcessEnvironmentBlock;
}


/*++

Memory writes

--*/
auto
mem::write(_In_ HANDLE hProcess, _In_ uptr Address, _In_ u8* Data, _In_ size_t DataLength) -> size_t
{
    size_t dwNbWritten;
    if ( ::WriteProcessMemory(hProcess, reinterpret_cast<LPVOID>(Address), Data, DataLength, &dwNbWritten) != FALSE )
    {
        return dwNbWritten;
    }
    return -1;
}

auto
mem::write(_In_ uptr Address, _In_ u8* Data, _In_ size_t DataLength) -> size_t
{
    return mem::write(::GetCurrentProcess(), Address, Data, DataLength);
}

auto
mem::write(_In_ HANDLE hProcess, _In_ uptr Address, _In_ std::vector<u8>& Data) -> size_t
{
    return mem::write(hProcess, Address, Data.data(), Data.size());
}

auto
mem::write(_In_ uptr Address, _In_ std::vector<u8>& Data) -> size_t
{
    return mem::write(::GetCurrentProcess(), Address, Data.data(), Data.size());
}


/*++

Memory read functions

--*/

auto
mem::read(_In_ HANDLE hProcess, _In_ uptr Address, _In_ size_t DataLength) -> std::vector<u8>
{
    auto tmp = std::make_unique<u8[]>(DataLength);
    std::vector<u8> out;
    size_t dwNbRead;
    ::ReadProcessMemory(hProcess, reinterpret_cast<LPVOID>(Address), tmp.get(), DataLength, &dwNbRead);
    for ( size_t i = 0; i < dwNbRead; i++ )
    {
        out.push_back(tmp[i]);
    }
    return out;
}


auto
mem::read(_In_ uptr Address, _In_ size_t DataLength) -> std::vector<u8>
{
    return mem::read(::GetCurrentProcess(), Address, DataLength);
}


/*++

Memory allocate functions

--*/
auto
mem::alloc(_In_ HANDLE hProcess, _In_ size_t Size, _In_ const wchar_t Permission[3], _In_opt_ uptr Address) -> uptr
{
    auto flProtect = 0;
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
    auto buf = (uptr)::VirtualAllocEx(hProcess, reinterpret_cast<LPVOID>(Address), Size, MEM_COMMIT, flProtect);
    if ( buf != 0u )
    {
        ::ZeroMemory(reinterpret_cast<LPVOID>(buf), Size);
    }
    return buf;
}

auto
mem::alloc(_In_ size_t Size, _In_ const wchar_t Permission[3], _In_opt_ uptr Address) -> uptr
{
    return mem::alloc(::GetCurrentProcess(), Size, Permission, Address);
}


/*++

Memory free functions

--*/
auto
mem::free(_In_ HANDLE hProcess, _In_ uptr Address) -> uptr
{
    return (uptr)::VirtualFreeEx(hProcess, reinterpret_cast<LPVOID>(Address), 0, MEM_RELEASE);
}

auto
mem::free(_In_ uptr Address) -> uptr
{
    return mem::free(::GetCurrentProcess(), Address);
}


/*++



--*/
_Success_(return )
auto
is_elevated(_In_opt_ u32 dwPid) -> bool
{
    HANDLE hProcessToken = nullptr;
    bool bRes            = FALSE;

    HANDLE hProcess = dwPid != 0u ? ::OpenProcess(PROCESS_QUERY_INFORMATION, 0, dwPid) : ::GetCurrentProcess();
    if ( hProcess == nullptr )
    {
        perror(L"OpenProcess()");
        return FALSE;
    }

    do
    {
        if ( ::OpenProcessToken(hProcess, TOKEN_QUERY, &hProcessToken) == 0 )
        {
            perror(L"OpenProcessToken()");
            break;
        }

        TOKEN_ELEVATION TokenInfo = {0};
        DWORD dwReturnLength      = 0;
        if ( ::GetTokenInformation(
                 hProcessToken,
                 TokenElevation,
                 &TokenInfo,
                 sizeof(TOKEN_ELEVATION),
                 &dwReturnLength) == 0 )
        {
            perror(L"GetTokenInformation()");
            break;
        }

        bRes = TokenInfo.TokenIsElevated;
    } while ( 0 );


    if ( hProcessToken != nullptr )
    {
        ::CloseHandle(hProcessToken);
    }

    return bRes;
}


_Success_(return )
auto
add_privilege(_In_ const wchar_t* lpszPrivilegeName, _In_opt_ u32 dwPid) -> bool
{
    HANDLE hToken = INVALID_HANDLE_VALUE;
    bool bRes     = FALSE;

    HANDLE hProcess = dwPid != 0u ? ::OpenProcess(PROCESS_QUERY_INFORMATION, 0, dwPid) : ::GetCurrentProcess();
    if ( hProcess == nullptr )
    {
        perror(L"OpenProcess()");
        return FALSE;
    }

    bRes = ::OpenProcessToken(hProcess, TOKEN_ADJUST_PRIVILEGES, &hToken);
    if ( bRes != 0 )
    {
        LUID Luid = {
            0,
        };

        bRes = ::LookupPrivilegeValue(nullptr, lpszPrivilegeName, &Luid);
        if ( bRes != 0 )
        {
            size_t nBufferSize = sizeof(TOKEN_PRIVILEGES) + 1 * sizeof(LUID_AND_ATTRIBUTES);
            auto buffer        = std::make_unique<u8[]>(nBufferSize);
            if ( buffer )
            {
                auto NewState                      = (PTOKEN_PRIVILEGES)buffer.get();
                NewState->PrivilegeCount           = 1;
                NewState->Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
                NewState->Privileges[0].Luid       = Luid;

                bRes = static_cast<bool>(
                    ::AdjustTokenPrivileges(
                        hToken,
                        FALSE,
                        NewState,
                        0,
                        (PTOKEN_PRIVILEGES) nullptr,
                        (PDWORD) nullptr) != 0);

                if ( bRes != 0 )
                {
                    bRes = static_cast<bool>(GetLastError() != ERROR_NOT_ALL_ASSIGNED);
                }
            }
        }

        CloseHandle(hToken);
    }

    if ( hProcess != nullptr )
    {
        ::CloseHandle(hProcess);
    }

    return bRes;
}


/*++
Routine Description:
    Simple helper function to check a privilege by name on the current process.

Arguments:
    lpszPrivilegeName - the name (as a wide string) of the privilege
    dwPid - opt - the pid of the process to query (if not provided, use current process)

Return Value:
    Returns TRUE if the current has the privilege
--*/
_Success_(return )
auto
has_privilege(_In_ const wchar_t* lpwszPrivilegeName, _In_opt_ u32 dwPid) -> bool
{
    LUID Luid = {
        0,
    };
    BOOL bRes     = FALSE;
    BOOL bHasPriv = FALSE;
    HANDLE hToken = nullptr;

    if ( dwPid == 0u )
    {
        dwPid = ::GetCurrentProcessId();
    }

    auto hProcess = pwn::utils::GenericHandle(::OpenProcess(PROCESS_QUERY_INFORMATION, 0, dwPid));

    if ( !hProcess )
    {
        perror(L"OpenProcess()");
        return FALSE;
    }

    do
    {
        dbg(L"Checking for '{}' for PID=%d...\n", lpwszPrivilegeName, dwPid);

        bRes = LookupPrivilegeValue(nullptr, lpwszPrivilegeName, &Luid);
        if ( bRes == 0 )
        {
            perror(L"LookupPrivilegeValue");
            break;
        }

        LUID_AND_ATTRIBUTES PrivAttr = {{0}};
        PrivAttr.Luid                = Luid;
        PrivAttr.Attributes          = SE_PRIVILEGE_ENABLED | SE_PRIVILEGE_ENABLED_BY_DEFAULT;

        PRIVILEGE_SET PrivSet = {
            0,
        };
        PrivSet.PrivilegeCount = 1;
        PrivSet.Privilege[0]   = PrivAttr;

        bRes = ::OpenProcessToken(hProcess.get(), TOKEN_QUERY, &hToken);
        if ( bRes == 0 )
        {
            perror(L"OpenProcessToken");
            break;
        }

        bRes = ::PrivilegeCheck(hToken, &PrivSet, &bHasPriv);
        if ( bRes == 0 )
        {
            perror(L"PrivilegeCheck");
            break;
        }

        bRes = bHasPriv;
    } while ( 0 );


    if ( hToken != nullptr )
    {
        ::CloseHandle(hToken);
    }

    return bRes == TRUE;
}


appcontainer::AppContainer::AppContainer(
    _In_ std::wstring container_name,
    _In_ std::wstring executable_path,
    _In_ std::vector<WELL_KNOWN_SID_TYPE> desired_capabilities) :
    m_ExecutablePath(std::move(executable_path)),
    m_ContainerName(std::move(container_name)),
    m_Capabilities(std::move(desired_capabilities))
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
    return allow_file_or_directory(file_or_directory_name.c_str());
}

_Success_(return )
auto
appcontainer::AppContainer::allow_file_or_directory(_In_ const wchar_t* file_or_directory_name) -> bool
{
    return set_named_object_access((PWSTR)file_or_directory_name, SE_FILE_OBJECT, GRANT_ACCESS, FILE_ALL_ACCESS);
}

_Success_(return )
auto
appcontainer::AppContainer::allow_registry_key(_In_ const std::wstring& regkey) -> bool
{
    return allow_file_or_directory(regkey.c_str());
}

_Success_(return )
auto
appcontainer::AppContainer::allow_registry_key(_In_ const wchar_t* regkey) -> bool
{
    return set_named_object_access((PWSTR)regkey, SE_REGISTRY_KEY, GRANT_ACCESS, FILE_ALL_ACCESS);
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
    _In_ PWSTR ObjectName,
    _In_ SE_OBJECT_TYPE ObjectType,
    _In_ ACCESS_MODE AccessMode,
    _In_ ACCESS_MASK AccessMask) -> bool
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
        dwRes = ::GetNamedSecurityInfo(
            ObjectName,
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
        dwRes = ::SetNamedSecurityInfo(
            ObjectName,
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
appcontainer::AppContainer::join(_In_ u32 dwTimeout) -> bool
{
    return ::WaitForSingleObject(m_ProcessInfo.hProcess, dwTimeout) != 0;
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


} // namespace pwn::win::process
