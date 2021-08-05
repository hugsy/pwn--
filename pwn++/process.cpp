#include "process.h"

#include "log.h"
#include "system.h"

using namespace pwn::log;

#include <accctrl.h>
#include <aclapi.h>
#include <psapi.h>
#include <sddl.h>
#include <shellapi.h>
#include <userenv.h>

#include <stdexcept>
#include <utility>

#include "handle.h"
#include "utils.h"


///
/// Note: this is just a fake excuse to use assembly in VS, for real world use `NtCurrentTeb()`
///
#ifdef _WIN64
#define TEB_OFFSET 0x30
#define PEB_OFFSET 0x60
extern "C" auto
x64_get_teb() -> ULONG_PTR;
#define get_teb x64_get_teb
#else
#define TEB_OFFSET 0x18
#define PEB_OFFSET 0x30
extern "C" ULONG_PTR
x86_get_teb();
#define get_teb x86_get_teb
#endif


auto
pwn::process::pid() -> DWORD
{
    return ::GetCurrentProcessId();
}


auto
pwn::process::ppid() -> DWORD
{
    return pwn::system::ppid(pid());
}


auto
pwn::process::list() -> std::vector<std::tuple<std::wstring, DWORD>>
{
    u16 maxCount = 256;
    std::unique_ptr<DWORD[]> pids;
    int count = 0;
    std::vector<std::tuple<std::wstring, DWORD>> processes;

    for (;;)
    {
        pids = std::make_unique<DWORD[]>(maxCount);
        DWORD actualSize;
        if (::EnumProcesses(pids.get(), maxCount * sizeof(DWORD), &actualSize) == 0)
        {
            break;
        }

        count = actualSize / sizeof(DWORD);

        if (count < maxCount)
        {
            break; // need to resize
        }

        maxCount *= 2;
    }

    for (int i = 0; i < count; i++)
    {
        DWORD pid = pids[i];
        pwn::utils::GenericHandle hProcess(::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid));
        if (!hProcess)
        {
            continue;
        }

        WCHAR exeName[MAX_PATH];
        DWORD size  = MAX_PATH;
        DWORD count = ::QueryFullProcessImageName(hProcess.get(), 0, exeName, &size);

        processes.emplace_back(exeName, pid);
    }

    return processes;
}


_Success_(return == ERROR_SUCCESS) auto pwn::process::get_integrity_level(_In_ DWORD dwProcessId, _Out_ std::wstring &IntegrityLevelName) -> DWORD
{
    DWORD dwRes            = ERROR_SUCCESS;
    DWORD dwIntegrityLevel = SECURITY_MANDATORY_MEDIUM_RID;

    do
    {
        auto hProcessHandle = pwn::utils::GenericHandle(::OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, dwProcessId));
        if (!hProcessHandle)
        {
            dwRes = ::GetLastError();
            break;
        }

        HANDLE hToken;
        if (::OpenProcessToken(hProcessHandle.get(), TOKEN_QUERY, &hToken) == 0)
        {
            dwRes = ::GetLastError();
            break;
        }

        auto hProcessToken = pwn::utils::GenericHandle(hToken);

        DWORD dwLengthNeeded = 0;

        if (::GetTokenInformation(hProcessToken.get(), TokenIntegrityLevel, nullptr, 0, &dwLengthNeeded) == 0)
        {
            dwRes = ::GetLastError();
            if (dwRes != ERROR_INSUFFICIENT_BUFFER)
            {
                dwRes = ::GetLastError();
                break;
            }
        }

        auto pTokenBuffer = reinterpret_cast<PTOKEN_MANDATORY_LABEL>(::LocalAlloc(LPTR, dwLengthNeeded));
        auto pTIL         = pwn::utils::GenericHandle(
            pTokenBuffer,
            [&]()
            {
                return ::LocalFree(pTokenBuffer) == nullptr;
            });

        if (!pTIL)
        {
            dwRes = ::GetLastError();
            break;
        }


        if (::GetTokenInformation(hProcessToken.get(), TokenIntegrityLevel, pTIL.get(), dwLengthNeeded, &dwLengthNeeded) == 0)
        {
            dwRes = ::GetLastError();
            if (dwRes != ERROR_INSUFFICIENT_BUFFER)
            {
                dwRes = ::GetLastError();
                break;
            }
        }

        dwIntegrityLevel = *::GetSidSubAuthority(pTIL.get()->Label.Sid, (DWORD)(UCHAR)(*::GetSidSubAuthorityCount(pTIL.get()->Label.Sid) - 1));

        if (dwIntegrityLevel == SECURITY_MANDATORY_LOW_RID)
        {
            IntegrityLevelName = L"Low";
        }
        else if (SECURITY_MANDATORY_MEDIUM_RID < dwIntegrityLevel && dwIntegrityLevel < SECURITY_MANDATORY_HIGH_RID)
        {
            IntegrityLevelName = L"Medium";
        }
        else if (dwIntegrityLevel >= SECURITY_MANDATORY_HIGH_RID)
        {
            IntegrityLevelName = L"High";
        }
        else if (dwIntegrityLevel >= SECURITY_MANDATORY_SYSTEM_RID)
        {
            IntegrityLevelName = L"System";
        }
        else
        {
            IntegrityLevelName = L"Unknown";
        }

        dwRes = ERROR_SUCCESS;

    } while (0);

    return dwRes;
}


_Success_(return == ERROR_SUCCESS) auto pwn::process::get_integrity_level(_Out_ std::wstring &IntegrityLevelName) -> DWORD
{
    return get_integrity_level(::GetCurrentProcessId(), IntegrityLevelName);
}


auto
pwn::process::get_integrity_level() -> std::optional<std::wstring>
{
    std::wstring IntegrityLevelName;
    if (get_integrity_level(::GetCurrentProcessId(), IntegrityLevelName) == ERROR_SUCCESS)
    {
        return IntegrityLevelName;
    }
    return std::nullopt;
}


_Success_(return ) auto pwn::process::execv(_In_ const wchar_t *lpCommandLine, _In_ DWORD dwParentPid, _Out_ LPHANDLE lpNewProcessHandle) -> BOOL
{
    HANDLE hParentProcess = nullptr;
    STARTUPINFOEX si      = {
        {0},
    };
    PROCESS_INFORMATION pi = {
        nullptr,
    };
    DWORD dwFlags     = EXTENDED_STARTUPINFO_PRESENT | CREATE_NEW_CONSOLE;
    si.StartupInfo.cb = sizeof(STARTUPINFOEX);

    size_t cmd_len = ::wcslen(lpCommandLine);

    auto cmd = std::make_unique<WCHAR[]>(cmd_len + 1);
    ::RtlCopyMemory(cmd.get(), lpCommandLine, 2 * cmd_len);

    if (dwParentPid != 0u)
    {
        hParentProcess = ::OpenProcess(PROCESS_CREATE_PROCESS, FALSE, dwParentPid);
        if (hParentProcess != nullptr)
        {
            SIZE_T AttrListSize = 0;
            ::InitializeProcThreadAttributeList(nullptr, 1, 0, &AttrListSize);
            si.lpAttributeList = (LPPROC_THREAD_ATTRIBUTE_LIST)::HeapAlloc(::GetProcessHeap(), 0, AttrListSize);
            if (si.lpAttributeList != nullptr)
            {
                ::InitializeProcThreadAttributeList(si.lpAttributeList, 1, 0, &AttrListSize);
                ::UpdateProcThreadAttribute(si.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &hParentProcess, sizeof(HANDLE), nullptr, nullptr);
                dbg(L"Spawning '%s' with PPID=%d...\n", cmd.get(), dwParentPid);
            }
        }
        else
        {
            perror(L"OpenProcess()");
        }
    }
    else
    {
        dbg(L"Spawning '%s'...\n", cmd.get());
    }

    if (::CreateProcess(nullptr, cmd.get(), nullptr, nullptr, 1, dwFlags, nullptr, nullptr, (LPSTARTUPINFO)&si, &pi) == 0)
    {
        perror(L"CreateProcess()");
        return FALSE;
    }

    ::CloseHandle(pi.hThread);
    if (dwParentPid != 0u)
    {
        if (si.lpAttributeList != nullptr)
        {
            ::DeleteProcThreadAttributeList(si.lpAttributeList);
            ::HeapFree(::GetProcessHeap(), 0, si.lpAttributeList);
        }

        if (hParentProcess != nullptr)
        {
            ::CloseHandle(hParentProcess);
        }
    }

    dbg(L"'%s' spawned with PID %d\n", lpCommandLine, pi.dwProcessId);
    if (lpNewProcessHandle != nullptr)
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
pwn::process::execv(_In_ const wchar_t *lpCommandLine, _In_ DWORD dwParentPid) -> std::optional<HANDLE>
{
    HANDLE hProcess = INVALID_HANDLE_VALUE;
    if (pwn::process::execv(lpCommandLine, dwParentPid, &hProcess) != 0)
    {
        return hProcess;
    }
    return std::nullopt;
}


_Success_(return ) auto pwn::process::system(_In_ const std::wstring &lpCommandLine, _In_ const std::wstring &operation) -> BOOL
{
    auto args = pwn::utils::split(lpCommandLine, L' ');
    auto cmd{args[0]};
    args.erase(args.begin());
    auto params = pwn::utils::join(args);

    return static_cast<BOOL>(reinterpret_cast<long long>(::ShellExecuteW(nullptr, operation.c_str(), cmd.c_str(), params.c_str(), nullptr, SW_SHOW)) > 32);
}


_Success_(return ) auto pwn::process::kill(_In_ DWORD dwProcessPid) -> BOOL
{
    HANDLE hProcess = ::OpenProcess(PROCESS_TERMINATE, FALSE, dwProcessPid);
    if (hProcess == nullptr)
    {
        return FALSE;
    }
    return kill(hProcess);
}


_Success_(return ) auto pwn::process::kill(_In_ HANDLE hProcess) -> BOOL
{
    dbg(L"attempting to kill %u (pid=%u)\n", hProcess, ::GetProcessId(hProcess));
    BOOL res = ::TerminateProcess(hProcess, EXIT_FAILURE);
    ::CloseHandle(hProcess);
    return res;
}


_Success_(return != nullptr) auto pwn::process::cmd() -> HANDLE
{
    auto hProcess = pwn::process::execv(L"cmd.exe");
    return hProcess ? hProcess.value() : INVALID_HANDLE_VALUE;
}


/*++

Get the TEB address of the current process

--*/
auto
pwn::process::teb() -> PTEB
{
    return NtCurrentTeb();
}


/*++

Get the PEB address of the current process

--*/
auto
pwn::process::peb() -> PPEB
{
    return teb()->ProcessEnvironmentBlock;
}


/*++

Memory writes

--*/
auto
pwn::process::mem::write(_In_ HANDLE hProcess, _In_ ULONG_PTR Address, _In_ PBYTE Data, _In_ SIZE_T DataLength) -> SIZE_T
{
    SIZE_T dwNbWritten;
    if (::WriteProcessMemory(hProcess, reinterpret_cast<LPVOID>(Address), Data, DataLength, &dwNbWritten) != FALSE)
    {
        return dwNbWritten;
    }
    return -1;
}

auto
pwn::process::mem::write(_In_ ULONG_PTR Address, _In_ PBYTE Data, _In_ SIZE_T DataLength) -> SIZE_T
{
    return pwn::process::mem::write(::GetCurrentProcess(), Address, Data, DataLength);
}

auto
pwn::process::mem::write(_In_ HANDLE hProcess, _In_ ULONG_PTR Address, _In_ std::vector<BYTE> &Data) -> SIZE_T
{
    return pwn::process::mem::write(hProcess, Address, Data.data(), Data.size());
}

auto
pwn::process::mem::write(_In_ ULONG_PTR Address, _In_ std::vector<BYTE> &Data) -> SIZE_T
{
    return pwn::process::mem::write(::GetCurrentProcess(), Address, Data.data(), Data.size());
}


/*++

Memory read functions

--*/

auto
pwn::process::mem::read(_In_ HANDLE hProcess, _In_ ULONG_PTR Address, _In_ SIZE_T DataLength) -> std::vector<BYTE>
{
    auto tmp = std::make_unique<BYTE[]>(DataLength);
    std::vector<BYTE> out;
    SIZE_T dwNbRead;
    ::ReadProcessMemory(hProcess, reinterpret_cast<LPVOID>(Address), tmp.get(), DataLength, &dwNbRead);
    for (size_t i = 0; i < dwNbRead; i++)
    {
        out.push_back(tmp[i]);
    }
    return out;
}


auto
pwn::process::mem::read(_In_ ULONG_PTR Address, _In_ SIZE_T DataLength) -> std::vector<BYTE>
{
    return pwn::process::mem::read(::GetCurrentProcess(), Address, DataLength);
}


/*++

Memory allocate functions

--*/
auto
pwn::process::mem::alloc(_In_ HANDLE hProcess, _In_ SIZE_T Size, _In_ const wchar_t Permission[3], _In_opt_ ULONG_PTR Address) -> ULONG_PTR
{
    auto flProtect = 0;
    if (wcscmp(Permission, L"r") == 0)
    {
        flProtect |= PAGE_READONLY;
    }
    if (wcscmp(Permission, L"rx") == 0)
    {
        flProtect |= PAGE_EXECUTE_READ;
    }
    if (wcscmp(Permission, L"rw") == 0)
    {
        flProtect |= PAGE_READWRITE;
    }
    if (wcscmp(Permission, L"rwx") == 0)
    {
        flProtect |= PAGE_EXECUTE_READWRITE;
    }
    auto buf = (ULONG_PTR)::VirtualAllocEx(hProcess, reinterpret_cast<LPVOID>(Address), Size, MEM_COMMIT, flProtect);
    if (buf != 0u)
    {
        ::ZeroMemory(reinterpret_cast<LPVOID>(buf), Size);
    }
    return buf;
}

auto
pwn::process::mem::alloc(_In_ SIZE_T Size, _In_ const wchar_t Permission[3], _In_opt_ ULONG_PTR Address) -> ULONG_PTR
{
    return pwn::process::mem::alloc(::GetCurrentProcess(), Size, Permission, Address);
}


/*++

Memory free functions

--*/
auto
pwn::process::mem::free(_In_ HANDLE hProcess, _In_ ULONG_PTR Address) -> ULONG_PTR
{
    return (ULONG_PTR)::VirtualFreeEx(hProcess, reinterpret_cast<LPVOID>(Address), 0, MEM_RELEASE);
}

auto
pwn::process::mem::free(_In_ ULONG_PTR Address) -> ULONG_PTR
{
    return pwn::process::mem::free(::GetCurrentProcess(), Address);
}


/*++



--*/
_Success_(return ) auto pwn::process::is_elevated(_In_opt_ DWORD dwPid) -> BOOL
{
    HANDLE hProcessToken = nullptr;
    BOOL bRes            = FALSE;

    HANDLE hProcess = dwPid != 0u ? ::OpenProcess(PROCESS_QUERY_INFORMATION, 0, dwPid) : ::GetCurrentProcess();
    if (hProcess == nullptr)
    {
        perror(L"OpenProcess()");
        return FALSE;
    }

    do
    {
        if (::OpenProcessToken(hProcess, TOKEN_QUERY, &hProcessToken) == 0)
        {
            perror(L"OpenProcessToken()");
            break;
        }

        TOKEN_ELEVATION TokenInfo = {0};
        DWORD dwReturnLength      = 0;
        if (::GetTokenInformation(hProcessToken, TokenElevation, &TokenInfo, sizeof(TOKEN_ELEVATION), &dwReturnLength) == 0)
        {
            perror(L"GetTokenInformation()");
            break;
        }

        bRes = TokenInfo.TokenIsElevated;
    } while (0);


    if (hProcessToken != nullptr)
    {
        ::CloseHandle(hProcessToken);
    }

    return bRes;
}


_Success_(return ) auto pwn::process::add_privilege(_In_ const wchar_t *lpszPrivilegeName, _In_opt_ DWORD dwPid) -> BOOL
{
    HANDLE hToken = INVALID_HANDLE_VALUE;
    BOOL bRes     = FALSE;

    HANDLE hProcess = dwPid != 0u ? ::OpenProcess(PROCESS_QUERY_INFORMATION, 0, dwPid) : ::GetCurrentProcess();
    if (hProcess == nullptr)
    {
        perror(L"OpenProcess()");
        return FALSE;
    }

    bRes = ::OpenProcessToken(hProcess, TOKEN_ADJUST_PRIVILEGES, &hToken);
    if (bRes != 0)
    {
        LUID Luid = {
            0,
        };

        bRes = ::LookupPrivilegeValue(nullptr, lpszPrivilegeName, &Luid);
        if (bRes != 0)
        {
            size_t nBufferSize = sizeof(TOKEN_PRIVILEGES) + 1 * sizeof(LUID_AND_ATTRIBUTES);
            auto buffer        = std::make_unique<std::byte[]>(nBufferSize);
            if (buffer)
            {
                auto NewState                      = (PTOKEN_PRIVILEGES)buffer.get();
                NewState->PrivilegeCount           = 1;
                NewState->Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
                NewState->Privileges[0].Luid       = Luid;

                bRes = static_cast<BOOL>(::AdjustTokenPrivileges(hToken, FALSE, NewState, 0, (PTOKEN_PRIVILEGES) nullptr, (PDWORD) nullptr) != 0);

                if (bRes != 0)
                {
                    bRes = static_cast<BOOL>(GetLastError() != ERROR_NOT_ALL_ASSIGNED);
                }
            }
        }

        CloseHandle(hToken);
    }

    if (hProcess != nullptr)
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
_Success_(return ) auto pwn::process::has_privilege(_In_ const wchar_t *lpwszPrivilegeName, _In_opt_ DWORD dwPid) -> BOOL
{
    LUID Luid = {
        0,
    };
    BOOL bRes     = FALSE;
    BOOL bHasPriv = FALSE;
    HANDLE hToken = nullptr;

    if (dwPid == 0u)
    {
        dwPid = ::GetCurrentProcessId();
    }

    auto hProcess = pwn::utils::GenericHandle(::OpenProcess(PROCESS_QUERY_INFORMATION, 0, dwPid));

    if (!hProcess)
    {
        perror(L"OpenProcess()");
        return FALSE;
    }

    do
    {
        dbg(L"Checking for '%s' for PID=%d...\n", lpwszPrivilegeName, dwPid);

        bRes = LookupPrivilegeValue(nullptr, lpwszPrivilegeName, &Luid);
        if (bRes == 0)
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
        if (bRes == 0)
        {
            perror(L"OpenProcessToken");
            break;
        }

        bRes = ::PrivilegeCheck(hToken, &PrivSet, &bHasPriv);
        if (bRes == 0)
        {
            perror(L"PrivilegeCheck");
            break;
        }

        bRes = bHasPriv;
    } while (0);


    if (hToken != nullptr)
    {
        ::CloseHandle(hToken);
    }

    return bRes;
}


pwn::process::appcontainer::AppContainer::AppContainer(_In_ std::wstring container_name, _In_ std::wstring executable_path, _In_ std::vector<WELL_KNOWN_SID_TYPE> desired_capabilities)
    : m_ExecutablePath(std::move(executable_path)),
      m_ContainerName(std::move(container_name)),
      m_Capabilities(std::move(desired_capabilities))
{
    auto hRes = ::CreateAppContainerProfile(m_ContainerName.c_str(), m_ContainerName.c_str(), m_ContainerName.c_str(), nullptr, 0, &m_AppContainerSid);

    if (FAILED(hRes))
    {
        hRes = ::DeriveAppContainerSidFromAppContainerName(m_ContainerName.c_str(), &m_AppContainerSid);
        if (FAILED(hRes))
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

    dbg(L"sid=%s\n", m_SidAsString.c_str());

    //
    // Get the folder path
    //
    PWSTR path;
    if (SUCCEEDED(::GetAppContainerFolderPath(m_SidAsString.c_str(), &path)))
    {
        m_FolderPath = path;
        ::CoTaskMemFree(path);
    }

    dbg(L"folder_path=%s\n", m_FolderPath.c_str());


    //
    // set the capabilities if any
    //
    m_SecurityCapabilities.AppContainerSid = m_AppContainerSid;
    auto dwNumberOfDesiredAttributes       = (DWORD)m_Capabilities.size();

    if (dwNumberOfDesiredAttributes != 0u)
    {
        //
        // populate the entries
        //
        auto dwNumberOfValidDesiredAttributes = 0;
        auto DesiredAttributes                = std::make_unique<SID_AND_ATTRIBUTES[]>(dwNumberOfDesiredAttributes);
        for (size_t i = 0; i < dwNumberOfDesiredAttributes; i++)
        {
            auto &Attribute = DesiredAttributes[i];
            auto Sid        = std::make_unique<BYTE[]>(SECURITY_MAX_SID_SIZE);
            DWORD cbSid     = SECURITY_MAX_SID_SIZE;
            if (::CreateWellKnownSid(m_Capabilities.at(i), nullptr, Sid.get(), &cbSid) == 0)
            {
                continue;
            }

            Attribute.Attributes = SE_GROUP_ENABLED;
            Attribute.Sid        = (PSID) new byte[cbSid];
            ::RtlCopyMemory(Attribute.Sid, Sid.get(), cbSid);
            dwNumberOfValidDesiredAttributes++;
        }


        //
        // fill up the security capabilities
        //

        if (dwNumberOfValidDesiredAttributes != 0)
        {
            m_SecurityCapabilities.CapabilityCount = dwNumberOfValidDesiredAttributes;
            m_SecurityCapabilities.Capabilities    = (PSID_AND_ATTRIBUTES) new byte[dwNumberOfValidDesiredAttributes * sizeof(SID_AND_ATTRIBUTES)];
            ::RtlCopyMemory(m_SecurityCapabilities.Capabilities, DesiredAttributes.get(), dwNumberOfValidDesiredAttributes * sizeof(SID_AND_ATTRIBUTES));
        }
    }


    //
    // build the startup info
    //
    SIZE_T size = 0;
    ::InitializeProcThreadAttributeList(nullptr, 1, 0, &size);
    if (size == 0u)
    {
        throw std::runtime_error("InitializeProcThreadAttributeList() failed");
    }

    m_StartupInfo.StartupInfo.cb  = sizeof(STARTUPINFOEX);
    m_StartupInfo.lpAttributeList = (LPPROC_THREAD_ATTRIBUTE_LIST)::new byte[size];

    if (::InitializeProcThreadAttributeList(m_StartupInfo.lpAttributeList, 1, 0, &size) == 0)
    {
        throw std::runtime_error("InitializeProcThreadAttributeList() failed");
    }

    if (::UpdateProcThreadAttribute(m_StartupInfo.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES, &m_SecurityCapabilities, sizeof(m_SecurityCapabilities), nullptr, nullptr) == 0)
    {
        throw std::runtime_error("UpdateProcThreadAttribute() failed");
    }
}


pwn::process::appcontainer::AppContainer::~AppContainer()
{
    dbg(L"freeing container '%s'\n", m_SidAsString.c_str());

    if (m_SecurityCapabilities.CapabilityCount != 0u)
    {
        for (DWORD i = 0; i < m_SecurityCapabilities.CapabilityCount; i++)
        {
            delete[] m_SecurityCapabilities.Capabilities[i].Sid;
        }
        delete[](byte *) m_SecurityCapabilities.Capabilities;
    }

    if (m_StartupInfo.lpAttributeList != nullptr)
    {
        delete[](byte *) m_StartupInfo.lpAttributeList;
    }

    if (m_AppContainerSid != nullptr)
    {
        ::FreeSid(m_AppContainerSid);
    }
}


_Success_(return ) auto pwn::process::appcontainer::AppContainer::allow_file_or_directory(_In_ const std::wstring &file_or_directory_name) -> BOOL
{
    return allow_file_or_directory(file_or_directory_name.c_str());
}

_Success_(return ) auto pwn::process::appcontainer::AppContainer::allow_file_or_directory(_In_ const wchar_t *file_or_directory_name) -> BOOL
{
    return set_named_object_access((PWSTR)file_or_directory_name, SE_FILE_OBJECT, GRANT_ACCESS, FILE_ALL_ACCESS);
}

_Success_(return ) auto pwn::process::appcontainer::AppContainer::allow_registry_key(_In_ const std::wstring &regkey) -> BOOL
{
    return allow_file_or_directory(regkey.c_str());
}

_Success_(return ) auto pwn::process::appcontainer::AppContainer::allow_registry_key(_In_ const wchar_t *regkey) -> BOOL
{
    return set_named_object_access((PWSTR)regkey, SE_REGISTRY_KEY, GRANT_ACCESS, FILE_ALL_ACCESS);
}

_Success_(return ) auto pwn::process::appcontainer::AppContainer::spawn() -> BOOL
{
    auto length     = m_ExecutablePath.length();
    auto sz         = length * 2;
    auto lpwCmdLine = std::make_unique<WCHAR[]>(sz + 2);
    ::ZeroMemory(lpwCmdLine.get(), sz + 2);
    ::memcpy(lpwCmdLine.get(), m_ExecutablePath.c_str(), sz);

    dbg(L"launching '%s' in container '%s'\n", lpwCmdLine.get(), m_SidAsString.c_str());

    auto bRes = ::CreateProcessW(nullptr, (LPWSTR)lpwCmdLine.get(), nullptr, nullptr, 0, EXTENDED_STARTUPINFO_PRESENT, nullptr, nullptr, (LPSTARTUPINFO)&m_StartupInfo, &m_ProcessInfo);

    if (m_StartupInfo.lpAttributeList != nullptr)
    {
        ::DeleteProcThreadAttributeList(m_StartupInfo.lpAttributeList);
    }

    return bRes;
}


_Success_(return ) auto pwn::process::appcontainer::AppContainer::set_named_object_access(_In_ PWSTR ObjectName, _In_ SE_OBJECT_TYPE ObjectType, _In_ ACCESS_MODE AccessMode, _In_ ACCESS_MASK AccessMask) -> BOOL
{
    BOOL bRes    = FALSE;
    PACL pOldAcl = nullptr;
    PACL pNewAcl = nullptr;
    DWORD dwRes;
    EXPLICIT_ACCESS Access;
    PSECURITY_DESCRIPTOR pSD = nullptr;

    do
    {
        //
        // Get the old ACEs
        //
        dwRes = ::GetNamedSecurityInfo(ObjectName, ObjectType, DACL_SECURITY_INFORMATION, nullptr, nullptr, &pOldAcl, nullptr, &pSD);
        if (dwRes != ERROR_SUCCESS)
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
        if (dwRes != ERROR_SUCCESS)
        {
            break;
        }

        //
        // Apply to the object
        //
        dbg(L"%s access to object '%s' by container '%s'\n", AccessMode == GRANT_ACCESS ? L"Allowing" : L"Denying", ObjectName, m_SidAsString.c_str());
        dwRes = ::SetNamedSecurityInfo(ObjectName, ObjectType, DACL_SECURITY_INFORMATION, nullptr, nullptr, pNewAcl, nullptr);
        if (dwRes != ERROR_SUCCESS)
        {
            break;
        }


        //
        // Keep a reference to the old ACL so we can restore the original ACEs
        //
        m_OriginalAcls.emplace_back(ObjectName, ObjectType, pOldAcl);

        bRes = TRUE;
    } while (0);

    if (pNewAcl != nullptr)
    {
        ::LocalFree(pNewAcl);
    }

    if (pSD != nullptr)
    {
        ::LocalFree(pSD);
    }

    return bRes;
}


_Success_(return ) auto pwn::process::appcontainer::AppContainer::join(_In_ DWORD dwTimeout) -> BOOL
{
    return ::WaitForSingleObject(m_ProcessInfo.hProcess, dwTimeout) == WAIT_OBJECT_0 ? TRUE : FALSE;
}


_Success_(return ) auto pwn::process::appcontainer::AppContainer::restore_acls() -> BOOL
{
    BOOL bRes = TRUE;

    for (auto &acl : m_OriginalAcls)
    {
        auto const &ObjectName = std::get<0>(acl);
        auto const &ObjectType = std::get<1>(acl);
        auto const &pOldAcl    = std::get<2>(acl);
        dbg(L"restoring original acl for '%s'\n", ObjectName.c_str());
        bRes &= static_cast<int>(::SetNamedSecurityInfo((PWSTR)ObjectName.c_str(), ObjectType, DACL_SECURITY_INFORMATION, nullptr, nullptr, pOldAcl, nullptr) == ERROR_SUCCESS);
    }

    return bRes;
}
