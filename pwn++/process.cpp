#include "process.h"
#include "log.h"
#include "system.h"
using namespace pwn::log;

#include <psapi.h>
#include <userenv.h>
#include <accctrl.h>
#include <aclapi.h>
#include <sddl.h>



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


_Success_(return)
BOOL pwn::process::appcontainer::allow_named_object_access(
    _In_ PSID appContainerSid, 
    _In_ PWSTR name, 
    _In_ SE_OBJECT_TYPE type,
    _In_ ACCESS_MODE accessMode,
    _In_ ACCESS_MASK accessMask
) 
{
    PACL oldAcl, newAcl = nullptr;
    DWORD status;
    EXPLICIT_ACCESS access;
    
    do 
    {
        access.grfAccessMode = accessMode;
        access.grfAccessPermissions = accessMask;
        access.grfInheritance = OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE;
        access.Trustee.MultipleTrusteeOperation = NO_MULTIPLE_TRUSTEE;
        access.Trustee.pMultipleTrustee = nullptr;
        access.Trustee.ptstrName = (PWSTR)appContainerSid;
        access.Trustee.TrusteeForm = TRUSTEE_IS_SID;
        access.Trustee.TrusteeType = TRUSTEE_IS_GROUP;

        status = GetNamedSecurityInfo(name, type, DACL_SECURITY_INFORMATION, nullptr, nullptr, &oldAcl, nullptr, nullptr);
        if (status != ERROR_SUCCESS)
            return false;

        status = SetEntriesInAcl(1, &access, oldAcl, &newAcl);
        if (status != ERROR_SUCCESS)
            return false;

        status = SetNamedSecurityInfo(name, type, DACL_SECURITY_INFORMATION, nullptr, nullptr, newAcl, nullptr);
        if (status != ERROR_SUCCESS)
            break;
    } 
    while (0);

    if (newAcl)
        ::LocalFree(newAcl);

    return status == ERROR_SUCCESS;
}


_Success_(return)
BOOL pwn::process::appcontainer::create_appcontainer(
    _In_ const std::wstring & containerName,
    _In_ const std::wstring & exePath,
    _In_ const std::vector<std::wstring> & files_directories_allowed,
    _In_ const std::vector<std::wstring>& regkeys_allowed
)
{
    PSID appContainerSid;
    auto hr = ::CreateAppContainerProfile(
        containerName.c_str(),
        containerName.c_str(),
        containerName.c_str(),
        nullptr,
        0,
        &appContainerSid
    );

    if (FAILED(hr))
    {
        hr = ::DeriveAppContainerSidFromAppContainerName(containerName.c_str(), &appContainerSid);
        if (FAILED(hr))
            return FALSE;
    }

    PWSTR str;
    ::ConvertSidToStringSid(appContainerSid, &str);

    PWSTR path;
    if (SUCCEEDED(::GetAppContainerFolderPath(str, &path)))
        ::CoTaskMemFree(path);

    ::LocalFree(str);


    SECURITY_CAPABILITIES sc = { 0 };
    sc.AppContainerSid = appContainerSid;

    STARTUPINFOEX si = { sizeof(si) };
    PROCESS_INFORMATION pi;
    SIZE_T size;

    ::InitializeProcThreadAttributeList(nullptr, 1, 0, &size);
    auto buffer = std::make_unique<BYTE[]>(size);
    si.lpAttributeList = reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(buffer.get());

    if (!::InitializeProcThreadAttributeList(si.lpAttributeList, 1, 0, &size))
        return FALSE;

    if (!::UpdateProcThreadAttribute(si.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES, &sc, sizeof(sc), nullptr, nullptr))
        return FALSE;

    for(auto &file : files_directories_allowed)
        allow_named_object_access(appContainerSid, (PWSTR)file.c_str(), SE_FILE_OBJECT, GRANT_ACCESS, FILE_ALL_ACCESS);


    for(auto &regkey : regkeys_allowed)
        allow_named_object_access(appContainerSid, (PWSTR)regkey.c_str(), SE_REGISTRY_WOW64_32KEY, GRANT_ACCESS, KEY_ALL_ACCESS);


    BOOL bRes = ::CreateProcessW(
        nullptr, 
        (LPWSTR)exePath.c_str(), 
        nullptr, 
        nullptr, 
        FALSE,
        EXTENDED_STARTUPINFO_PRESENT, 
        nullptr, 
        nullptr, 
        (LPSTARTUPINFO)&si, 
        &pi
    );

    ::DeleteProcThreadAttributeList(si.lpAttributeList);

    return bRes;
}
