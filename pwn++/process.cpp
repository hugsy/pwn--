#include "process.h"
#include "log.h"
#include "system.h"

using namespace pwn::log;

#include <psapi.h>
#include <userenv.h>
#include <accctrl.h>
#include <aclapi.h>
#include <sddl.h>
#include <stdexcept>
#include <shellapi.h>
#include "utils.h"



#ifdef _WIN64
extern "C" ULONG_PTR __asm__get_teb_x64();
#define PEB_OFFSET 0x60
#define __asm__get_teb __asm__get_teb_x64
#else
extern "C" ULONG_PTR __asm__get_teb_x86();
#define PEB_OFFSET 0x30
#define __asm__get_teb __asm__get_teb_x86
#endif




DWORD pwn::process::pid()
{
    return ::GetCurrentProcessId();
}


DWORD pwn::process::ppid()
{
    return pwn::system::ppid(pid());
}


std::vector<pwn::process::process_t> pwn::process::list()
{
    int maxCount = 256; 
    std::unique_ptr<DWORD[]> pids; 
    int count = 0; 
    std::vector<pwn::process::process_t> processes;

    for (;;) 
    {
        pids = std::make_unique<DWORD[]>(maxCount); 
        DWORD actualSize; 
        if ( !::EnumProcesses(pids.get(), maxCount * sizeof(DWORD), &actualSize) )
            break; 
        
        count = actualSize / sizeof(DWORD); 
        
        if ( count < maxCount )
            break;// need to resize
        
        maxCount*=2;
    }
    
    for ( int i = 0; i < count; i++ )
    {
        DWORD pid = pids[i];
        HANDLE hProcess = ::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
        if ( !hProcess )
            continue;

        WCHAR exeName[MAX_PATH];
        DWORD size = MAX_PATH;
        DWORD count = ::QueryFullProcessImageName(hProcess, 0, exeName, &size);

        pwn::process::process_t p;
        p.name = std::wstring(exeName);
        p.pid = pid;
        processes.push_back(p);
        ::CloseHandle(hProcess);
    }

    return processes;
}



_Success_(return == ERROR_SUCCESS)
DWORD pwn::process::get_integrity_level(_In_ DWORD dwProcessId, _Out_ std::wstring & IntegrityLevelName)
{
    HANDLE hProcessHandle = INVALID_HANDLE_VALUE;
    HANDLE hProcessToken = INVALID_HANDLE_VALUE;
    DWORD dwRes = ERROR_SUCCESS;
    PTOKEN_MANDATORY_LABEL pTIL = NULL;
    DWORD dwIntegrityLevel = SECURITY_MANDATORY_MEDIUM_RID;

    do
    {
        hProcessHandle = ::OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, dwProcessId);
        if (hProcessHandle == NULL)
        {
            dwRes = ::GetLastError();
            break;
        }

        if (!::OpenProcessToken(hProcessHandle, TOKEN_QUERY, &hProcessToken))
        {
            dwRes = ::GetLastError();
            break;
        }

        DWORD dwLengthNeeded;

        if (!::GetTokenInformation(hProcessToken, TokenIntegrityLevel, NULL, 0, &dwLengthNeeded))
        {
            dwRes = ::GetLastError();
            if (dwRes != ERROR_INSUFFICIENT_BUFFER)
            {
                dwRes = ::GetLastError();
                break;
            }
        }

        pTIL = (PTOKEN_MANDATORY_LABEL)::LocalAlloc(LPTR, dwLengthNeeded);
        if (!pTIL)
        {
            dwRes = ::GetLastError();
            break;
        }


        if (!::GetTokenInformation(hProcessToken, TokenIntegrityLevel, pTIL, dwLengthNeeded, &dwLengthNeeded))
        {
            dwRes = ::GetLastError();
            if (dwRes != ERROR_INSUFFICIENT_BUFFER)
            {
                dwRes = ::GetLastError();
                break;
            }
        }

        dwIntegrityLevel = *::GetSidSubAuthority(
            pTIL->Label.Sid,
            (DWORD)(UCHAR)(*::GetSidSubAuthorityCount(pTIL->Label.Sid) - 1)
        );

        ::LocalFree(pTIL);


        if (dwIntegrityLevel == SECURITY_MANDATORY_LOW_RID)
            IntegrityLevelName = L"Low";

        else if (SECURITY_MANDATORY_MEDIUM_RID < dwIntegrityLevel && dwIntegrityLevel < SECURITY_MANDATORY_HIGH_RID)
            IntegrityLevelName = L"Medium";

        else if (dwIntegrityLevel >= SECURITY_MANDATORY_HIGH_RID)
            IntegrityLevelName = L"High";

        else if (dwIntegrityLevel >= SECURITY_MANDATORY_SYSTEM_RID)
            IntegrityLevelName = L"System";

        else
            IntegrityLevelName = L"Unknown";

        dwRes = ERROR_SUCCESS;

    } while (0);

    if (hProcessToken != INVALID_HANDLE_VALUE)
        ::CloseHandle(hProcessToken);

    if (hProcessHandle)
        ::CloseHandle(hProcessHandle);

    return dwRes;
}


_Success_(return == ERROR_SUCCESS)
DWORD pwn::process::get_integrity_level(_Out_ std::wstring & IntegrityLevelName)
{
    return get_integrity_level(::GetCurrentProcessId(), IntegrityLevelName);
}


_Success_(return)
BOOL pwn::process::execv(_In_ const wchar_t* lpCommandLine, _In_opt_ DWORD dwParentPid, _Out_opt_ LPHANDLE lpNewProcessHandle)
{
    HANDLE hParentProcess = NULL;
    STARTUPINFOEX si = { 0, };
    PROCESS_INFORMATION pi = { 0, };
    DWORD dwFlags = EXTENDED_STARTUPINFO_PRESENT | CREATE_NEW_CONSOLE;
    si.StartupInfo.cb = sizeof(STARTUPINFOEX);
    
    size_t cmd_len = ::wcslen(lpCommandLine);

    auto cmd = std::make_unique<WCHAR[]>(cmd_len+1);
    ::RtlCopyMemory(cmd.get(), lpCommandLine, 2 * cmd_len);

    if ( dwParentPid )
    {
        hParentProcess = ::OpenProcess(PROCESS_CREATE_PROCESS, FALSE, dwParentPid);
        if ( hParentProcess )
        {
            SIZE_T AttrListSize = 0;
            ::InitializeProcThreadAttributeList(nullptr, 1, 0, &AttrListSize);
            si.lpAttributeList = (LPPROC_THREAD_ATTRIBUTE_LIST)::HeapAlloc(::GetProcessHeap(), 0, AttrListSize);
            if ( si.lpAttributeList )
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

    if (!::CreateProcess(NULL, cmd.get(), NULL, NULL, TRUE, dwFlags, NULL, NULL, (LPSTARTUPINFO)&si, &pi))
    {
        perror(L"CreateProcess()");
        return FALSE;
    }

    ::CloseHandle(pi.hThread);
    if ( dwParentPid)
    {
        if ( si.lpAttributeList )
        {
            ::DeleteProcThreadAttributeList(si.lpAttributeList);
            ::HeapFree(::GetProcessHeap(), 0, si.lpAttributeList);
        }

        if (hParentProcess)
            ::CloseHandle(hParentProcess);
    }

    dbg(L"'%s' spawned with PID %d\n", lpCommandLine, pi.dwProcessId);
    if(lpNewProcessHandle)
        *lpNewProcessHandle = pi.hProcess;
    else
        ::CloseHandle(pi.hProcess);

    return TRUE;
}


_Success_(return)
BOOL pwn::process::execv(_In_ const wchar_t* lpCommandLine, _Out_opt_ LPHANDLE lpNewProcessHandle)
{
    return pwn::process::execv(lpCommandLine, 0, lpNewProcessHandle);
}

_Success_(return)
BOOL pwn::process::system(_In_ const std::wstring& lpCommandLine, _In_ const std::wstring& operation)
{
    auto args = pwn::utils::split(lpCommandLine, L' ');
    auto cmd{ args[0] };
    args.erase(args.begin());
    auto params = pwn::utils::join(args);

    return reinterpret_cast<long long>(::ShellExecuteW(
        nullptr,
        operation.c_str(),
        cmd.c_str(),
        params.c_str(),
        nullptr,
        SW_SHOW
    )) > 32;
    
}


_Success_(return)
BOOL pwn::process::kill(_In_ DWORD dwProcessPid)
{
    HANDLE hProcess = ::OpenProcess(PROCESS_TERMINATE, FALSE, dwProcessPid);
    if ( !hProcess )
        return FALSE;
    return kill(hProcess);
}


_Success_(return)
BOOL pwn::process::kill(_In_ HANDLE hProcess)
{
    dbg(L"attempting to kill %u (pid=%u)\n", hProcess, ::GetProcessId(hProcess));
    BOOL res = ::TerminateProcess(hProcess, EXIT_FAILURE);
    ::CloseHandle(hProcess);
    return res;
}


_Success_(return != nullptr)
HANDLE pwn::process::cmd()
{
    HANDLE hProcess = nullptr;
    pwn::process::execv(L"cmd.exe", &hProcess);
    return hProcess;
}


/*++

Get the TEB address of the current process

--*/
PTEB pwn::process::teb()
{
    return (PTEB)__asm__get_teb();
}


/*++

Get the PEB address of the current process

--*/
PPEB pwn::process::peb()
{
    return pwn::process::teb()->ProcessEnvironmentBlock;
}


/*++

Memory writes

--*/
SIZE_T pwn::process::mem::write(_In_ HANDLE hProcess, _In_ ULONG_PTR Address, _In_ PBYTE Data, _In_ SIZE_T DataLength)
{
    size_t dwNbWritten;
    if ( ::WriteProcessMemory(hProcess, reinterpret_cast<LPVOID>(Address), Data, DataLength, &dwNbWritten) )
        return dwNbWritten;
    return -1;
}

SIZE_T pwn::process::mem::write(_In_ ULONG_PTR Address, _In_ PBYTE Data, _In_ SIZE_T DataLength)
{
    return pwn::process::mem::write(::GetCurrentProcess(), Address, Data, DataLength);
}

SIZE_T pwn::process::mem::write(_In_ HANDLE hProcess, _In_ ULONG_PTR Address, _In_ std::vector<BYTE>& Data)
{
    return pwn::process::mem::write(hProcess, Address, Data.data(), Data.size());
}

SIZE_T pwn::process::mem::write(_In_ ULONG_PTR Address, _In_ std::vector<BYTE>& Data)
{
    return pwn::process::mem::write(::GetCurrentProcess(), Address, Data.data(), Data.size());
}


/*++

Memory read functions

--*/

std::vector<BYTE> pwn::process::mem::read(_In_ HANDLE hProcess, _In_ ULONG_PTR Address, _In_ SIZE_T DataLength)
{
    auto tmp = std::make_unique<BYTE[]>(DataLength);
    std::vector<BYTE> out;
    size_t dwNbRead;
    ::ReadProcessMemory(hProcess, reinterpret_cast<LPVOID>(Address), tmp.get(), DataLength, &dwNbRead);
    for ( size_t i = 0; i < dwNbRead; i++ ) out.push_back(tmp[i]);
    return out;
}


std::vector<BYTE> pwn::process::mem::read(_In_ ULONG_PTR Address, _In_ SIZE_T DataLength)
{
    return pwn::process::mem::read(::GetCurrentProcess(), Address, DataLength);
}


/*++

Memory allocate functions

--*/
ULONG_PTR pwn::process::mem::alloc(_In_ HANDLE hProcess, _In_ SIZE_T Size, _In_ const wchar_t Permission[3], _In_opt_ ULONG_PTR Address)
{
    auto flProtect = 0;
    if( !wcscmp(Permission, L"r") ) flProtect |= PAGE_READONLY;
    if( !wcscmp(Permission, L"rx") ) flProtect |= PAGE_EXECUTE_READ;
    if( !wcscmp(Permission, L"rw") ) flProtect |= PAGE_READWRITE;
    if( !wcscmp(Permission, L"rwx") ) flProtect |= PAGE_EXECUTE_READWRITE;
    auto buf = (ULONG_PTR)::VirtualAllocEx(hProcess, reinterpret_cast<LPVOID>(Address), Size, MEM_COMMIT, flProtect);
    if ( buf )
        ::ZeroMemory(reinterpret_cast<LPVOID>(buf), Size);
    return buf;
}

ULONG_PTR pwn::process::mem::alloc(_In_ SIZE_T Size, _In_ const wchar_t Permission[3], _In_opt_ ULONG_PTR Address)
{
    return  pwn::process::mem::alloc(::GetCurrentProcess(), Size, Permission, Address);
}


/*++

Memory free functions

--*/
ULONG_PTR pwn::process::mem::free(_In_ HANDLE hProcess, _In_ ULONG_PTR Address)
{
    return (ULONG_PTR)::VirtualFreeEx(hProcess, reinterpret_cast<LPVOID>(Address), 0, MEM_RELEASE);
}

ULONG_PTR pwn::process::mem::free(_In_ ULONG_PTR Address)
{
    return  pwn::process::mem::free(::GetCurrentProcess(), Address);
}



/*++



--*/
_Success_(return)
BOOL pwn::process::is_elevated( _In_opt_ DWORD dwPid)
{
    HANDLE hProcessToken = nullptr;
    BOOL bRes = FALSE;

    HANDLE hProcess = dwPid ? ::OpenProcess(PROCESS_QUERY_INFORMATION, false, dwPid) : ::GetCurrentProcess();
    if ( hProcess == nullptr )
    {
        perror(L"OpenProcess()");
        return FALSE;
    }

    do
    {
        if ( !::OpenProcessToken(hProcess, TOKEN_QUERY, &hProcessToken) )
        {
            perror(L"OpenProcessToken()");
            break;
        }

        TOKEN_ELEVATION TokenInfo = { 0 };
        DWORD dwReturnLength = 0;
        if ( !::GetTokenInformation(hProcessToken, TokenElevation, &TokenInfo, sizeof(TOKEN_ELEVATION), &dwReturnLength) )
        {
            perror(L"GetTokenInformation()");
            break;
        }

        bRes = TokenInfo.TokenIsElevated;
    }
    while ( 0 );


    if( hProcessToken != nullptr )
        ::CloseHandle(hProcessToken);

    return bRes;
}




_Success_(return)
BOOL pwn::process::add_privilege(_In_ const wchar_t* lpszPrivilegeName, _In_opt_ DWORD dwPid)
{
    HANDLE hToken = INVALID_HANDLE_VALUE;
    BOOL bRes = FALSE;

    HANDLE hProcess = dwPid ? ::OpenProcess(PROCESS_QUERY_INFORMATION, false, dwPid) : ::GetCurrentProcess();
    if ( hProcess == nullptr )
    {
        perror(L"OpenProcess()");
        return FALSE;
    }

    bRes = ::OpenProcessToken(hProcess, TOKEN_QUERY, &hToken);
    if ( bRes )
    {
        LUID Luid = { 0, };

        bRes = ::LookupPrivilegeValue(NULL, lpszPrivilegeName, &Luid);
        if ( bRes )
        {
            size_t nBufferSize = sizeof(TOKEN_PRIVILEGES) + 1 * sizeof(LUID_AND_ATTRIBUTES);
            PTOKEN_PRIVILEGES NewState = (PTOKEN_PRIVILEGES)LocalAlloc(LPTR, nBufferSize);
            if ( NewState )
            {
                NewState->PrivilegeCount = 1;
                NewState->Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
                NewState->Privileges[0].Luid = Luid;

                bRes = ::AdjustTokenPrivileges(
                    hToken,
                    FALSE,
                    NewState,
                    0,
                    (PTOKEN_PRIVILEGES)NULL,
                    (PDWORD)NULL
                ) != 0;

                if ( bRes )
                    bRes = GetLastError() != ERROR_NOT_ALL_ASSIGNED;

                LocalFree(NewState);
            }
        }

        CloseHandle(hToken);
    }

    if ( hProcess != nullptr )
        ::CloseHandle(hProcess);

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
_Success_(return)
BOOL pwn::process::has_privilege(_In_ const wchar_t* lpwszPrivilegeName, _In_opt_ DWORD dwPid)
{
    LUID Luid = { 0, };
    BOOL bRes = FALSE, bHasPriv = FALSE;
    HANDLE hToken = INVALID_HANDLE_VALUE;

    HANDLE hProcess = dwPid ? ::OpenProcess(PROCESS_QUERY_INFORMATION, false, dwPid) : ::GetCurrentProcess();
    if ( hProcess == nullptr )
    {
        perror(L"OpenProcess()");
        return FALSE;
    }

    do
    {
        dbg(L"Checking for '%s' for PID=%d...\n", lpwszPrivilegeName, dwPid ? dwPid : ::GetCurrentProcessId());

        bRes = LookupPrivilegeValue(NULL, lpwszPrivilegeName, &Luid);
        if ( !bRes )
        {
            perror(L"LookupPrivilegeValue");
            break;
        }

        LUID_AND_ATTRIBUTES PrivAttr = { 0 };
        PrivAttr.Luid = Luid;
        PrivAttr.Attributes = SE_PRIVILEGE_ENABLED | SE_PRIVILEGE_ENABLED_BY_DEFAULT;

        PRIVILEGE_SET PrivSet = { 0, };
        PrivSet.PrivilegeCount = 1;
        PrivSet.Privilege[0] = PrivAttr;

        bRes = ::OpenProcessToken(hProcess, TOKEN_QUERY, &hToken);
        if ( !bRes )
        {
            perror(L"OpenProcessToken");
            break;
        }

        bRes = ::PrivilegeCheck(hToken, &PrivSet, &bHasPriv);
        if ( !bRes )
        {
            perror(L"PrivilegeCheck");
            break;
        }

        bRes = bHasPriv;
    }
    while ( 0 );


    if ( hToken != nullptr )
        ::CloseHandle(hToken);

    if (hProcess != nullptr)
        ::CloseHandle(hProcess);

    return bRes;
}




pwn::process::appcontainer::AppContainer::AppContainer(
    _In_ const std::wstring& container_name, 
    _In_ const std::wstring& executable_path,
    _In_ const std::vector<WELL_KNOWN_SID_TYPE>& desired_capabilities
)
    : 
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
        &m_AppContainerSid
    );

    if (FAILED(hRes))
    {
        hRes = ::DeriveAppContainerSidFromAppContainerName(m_ContainerName.c_str(), &m_AppContainerSid);
        if (FAILED(hRes))
            throw std::runtime_error("DeriveAppContainerSidFromAppContainerName() failed");
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
    auto dwNumberOfDesiredAttributes = (DWORD)m_Capabilities.size();

    if (dwNumberOfDesiredAttributes)
    {
        //
        // populate the entries
        //
        auto dwNumberOfValidDesiredAttributes = 0;
        auto DesiredAttributes = std::make_unique<SID_AND_ATTRIBUTES[]>(dwNumberOfDesiredAttributes); 
        for (size_t i = 0; i < dwNumberOfDesiredAttributes; i++)
        {
            auto& Attribute = DesiredAttributes[i];
            auto Sid = std::make_unique<BYTE[]>(SECURITY_MAX_SID_SIZE);
            DWORD cbSid = SECURITY_MAX_SID_SIZE;
            if (!::CreateWellKnownSid(m_Capabilities.at(i), nullptr, Sid.get(), &cbSid))
                continue;

            Attribute.Attributes = SE_GROUP_ENABLED;
            Attribute.Sid = (PSID) new byte[cbSid];
            ::RtlCopyMemory(Attribute.Sid, Sid.get(), cbSid);
            dwNumberOfValidDesiredAttributes++;
        }


        //
        // fill up the security capabilities
        //      

        if (dwNumberOfValidDesiredAttributes)
        {
            m_SecurityCapabilities.CapabilityCount = dwNumberOfValidDesiredAttributes;
            m_SecurityCapabilities.Capabilities = (PSID_AND_ATTRIBUTES) new byte[dwNumberOfValidDesiredAttributes * sizeof(SID_AND_ATTRIBUTES)];
            ::RtlCopyMemory(m_SecurityCapabilities.Capabilities, DesiredAttributes.get(), dwNumberOfValidDesiredAttributes * sizeof(SID_AND_ATTRIBUTES));
        }
    }


    //
    // build the startup info
    //   
    SIZE_T size;
    m_StartupInfo.StartupInfo.cb = sizeof(STARTUPINFOEX);
    ::InitializeProcThreadAttributeList(nullptr, 1, 0, &size);

    m_StartupInfo.lpAttributeList = (LPPROC_THREAD_ATTRIBUTE_LIST)::new byte[size];

    if (!::InitializeProcThreadAttributeList(m_StartupInfo.lpAttributeList, 1, 0, &size))
        throw std::runtime_error("InitializeProcThreadAttributeList() failed");

    if(!::UpdateProcThreadAttribute(m_StartupInfo.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES, &m_SecurityCapabilities, sizeof(m_SecurityCapabilities), nullptr, nullptr))
        throw std::runtime_error("UpdateProcThreadAttribute() failed");
}


pwn::process::appcontainer::AppContainer::~AppContainer()
{
    dbg(L"freeing container '%s'\n", m_SidAsString.c_str());

    if (m_SecurityCapabilities.CapabilityCount)
    {
        for (DWORD i = 0; i < m_SecurityCapabilities.CapabilityCount; i++)
            delete[] m_SecurityCapabilities.Capabilities[i].Sid;
        delete[] (byte*)m_SecurityCapabilities.Capabilities;
    }

    if (m_StartupInfo.lpAttributeList)
        delete[](byte*)m_StartupInfo.lpAttributeList;

    if (m_AppContainerSid)
        ::FreeSid(m_AppContainerSid);
}


_Success_(return)
BOOL pwn::process::appcontainer::AppContainer::allow_file_or_directory(_In_ const std::wstring& file_or_directory_name)
{
    return allow_file_or_directory(file_or_directory_name.c_str());
}

_Success_(return)
BOOL pwn::process::appcontainer::AppContainer::allow_file_or_directory(_In_ const wchar_t* file_or_directory_name)
{
    return set_named_object_access((PWSTR)file_or_directory_name, SE_FILE_OBJECT, GRANT_ACCESS, FILE_ALL_ACCESS);
}

_Success_(return)
BOOL pwn::process::appcontainer::AppContainer::allow_registry_key(_In_ const std::wstring& regkey)
{
    return allow_file_or_directory(regkey.c_str());
}

_Success_(return)
BOOL pwn::process::appcontainer::AppContainer::allow_registry_key(_In_ const wchar_t* regkey)
{
    return set_named_object_access((PWSTR)regkey, SE_REGISTRY_KEY, GRANT_ACCESS, FILE_ALL_ACCESS);
}

_Success_(return)
BOOL pwn::process::appcontainer::AppContainer::spawn()
{
    auto length = m_ExecutablePath.length();
    auto sz = length * 2;
    auto lpwCmdLine = std::make_unique<BYTE[]>(sz+2);
    ::ZeroMemory(lpwCmdLine.get(), sz+2);
    ::memcpy(lpwCmdLine.get(), m_ExecutablePath.c_str(), sz);

    dbg(L"launching '%s' in container '%s'\n", lpwCmdLine.get(), m_SidAsString.c_str());

    BOOL bRes = ::CreateProcessW(
        nullptr,
        (LPWSTR)lpwCmdLine.get(),
        nullptr,
        nullptr,
        FALSE,
        EXTENDED_STARTUPINFO_PRESENT,
        nullptr,
        nullptr,
        (LPSTARTUPINFO)&m_StartupInfo,
        &m_ProcessInfo
    );

    if (m_StartupInfo.lpAttributeList)
        ::DeleteProcThreadAttributeList(m_StartupInfo.lpAttributeList);

    return bRes;
}


_Success_(return)
BOOL pwn::process::appcontainer::AppContainer::set_named_object_access(
    _In_ PWSTR ObjectName, 
    _In_ SE_OBJECT_TYPE ObjectType, 
    _In_ ACCESS_MODE AccessMode, 
    _In_ ACCESS_MASK AccessMask
)
{
    BOOL bRes = FALSE;
    PACL pOldAcl = nullptr, pNewAcl = nullptr;
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
            break;

        //
        // Build the new one
        //
        ZeroMemory(&Access, sizeof(EXPLICIT_ACCESS));
        Access.grfAccessMode = AccessMode;
        Access.grfAccessPermissions = AccessMask;
        Access.grfInheritance = OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE;
        Access.Trustee.MultipleTrusteeOperation = NO_MULTIPLE_TRUSTEE;
        Access.Trustee.pMultipleTrustee = nullptr;
        Access.Trustee.ptstrName = (PWSTR)m_AppContainerSid;
        Access.Trustee.TrusteeForm = TRUSTEE_IS_SID;
        Access.Trustee.TrusteeType = TRUSTEE_IS_GROUP;

        dwRes = ::SetEntriesInAcl(1, &Access, pOldAcl, &pNewAcl);
        if (dwRes != ERROR_SUCCESS)
            break;

        //
        // Apply to the object
        //
        dbg(L"%s access to object '%s' by container '%s'\n", AccessMode==GRANT_ACCESS?L"Allowing":L"Denying", ObjectName, m_SidAsString.c_str());
        dwRes = ::SetNamedSecurityInfo(ObjectName, ObjectType, DACL_SECURITY_INFORMATION, nullptr, nullptr, pNewAcl, nullptr);
        if (dwRes != ERROR_SUCCESS)
            break;


        //
        // Keep a reference to the old ACL so we can restore the original ACEs
        //
        m_OriginalAcls.push_back({ ObjectName, ObjectType, pOldAcl });

        bRes = TRUE;
    } 
    while (0);

    if (pNewAcl)
        ::LocalFree(pNewAcl);

    if (pSD)
        ::LocalFree(pSD);

    return bRes;
}


_Success_(return)
BOOL pwn::process::appcontainer::AppContainer::join(_In_ DWORD dwTimeout)
{
    return ::WaitForSingleObject(m_ProcessInfo.hProcess, dwTimeout) == WAIT_OBJECT_0 ? TRUE : FALSE;
}


_Success_(return)
BOOL pwn::process::appcontainer::AppContainer::restore_acls()
{
    BOOL bRes = TRUE;

    for (auto& acl : m_OriginalAcls)
    {
        auto ObjectName = std::get<0>(acl);
        auto ObjectType = std::get<1>(acl);
        auto pOldAcl = std::get<2>(acl);
        dbg(L"restoring original acl for '%s'\n", ObjectName.c_str());
        bRes &= (::SetNamedSecurityInfo((PWSTR)ObjectName.c_str(), ObjectType, DACL_SECURITY_INFORMATION, nullptr, nullptr, pOldAcl, nullptr) == ERROR_SUCCESS);
    }

    return bRes;
}