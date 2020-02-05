#include "system.h"
#include "log.h"

#include <tlhelp32.h>


using namespace pwn::log;

#define SYSTEM_PROCESS_NAME L"System"
#define LSASS_PROCESS_NAME L"lsass.exe"
#define CSRSS_PROCESS_NAME L"csrss.exe"
#define CALC_PROCESS_NAME L"calc.exe"
#define CMD_PROCESS_NAME L"cmd.exe"

#define WINDOWS_SYSTEM32_PATH L"\\SystemRoot\\system32\\"

#define CALC_PATH WINDOWS_SYSTEM32_PATH CALC_PROCESS_NAME
#define CMD_PATH WINDOWS_SYSTEM32_PATH CMD_PROCESS_NAME
#define KERNEL_PROCESS_NAME WINDOWS_SYSTEM32_PATH L"ntoskrnl.exe"


DWORD pwn::system::pagesize()
{
    SYSTEM_INFO siSysInfo = { 0, };
    ::GetSystemInfo(&siSysInfo);
    return siSysInfo.dwPageSize;
}



DWORD pwn::system::pid()
{
    return ::GetCurrentProcessId();
}



DWORD pwn::system::ppid(_In_ DWORD dwProcessId)
{
    HANDLE hProcessSnap;
    PROCESSENTRY32 pe = { 0, };

    hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hProcessSnap == INVALID_HANDLE_VALUE)
    {
        perror(L"CreateToolhelp32Snapshot()");
        return -1;
    }

    pe.dwSize = sizeof(PROCESSENTRY32);
    int32_t dwPpid = -1;

    if (Process32First(hProcessSnap, &pe))
    {
        do 
        {
            if (pe.th32ProcessID == dwProcessId) 
            {
                dwPpid = pe.th32ParentProcessID;
                break;
            }
        } 
        while (Process32Next(hProcessSnap, &pe));
    }

    ::CloseHandle(hProcessSnap);
    return dwPpid;
}


DWORD pwn::system::ppid()
{
    return ppid(pid());
}


/*++

Description:

    Look up for a process name with the given argument, and return the PID of the first instance

Arguments:

    - lpwProcessName an LPWSTR of the name of the process to find

Returns:
    
    the PID of the first process if found, -1 if failure

 --*/
DWORD PWNAPI pwn::system::pidof(_In_ const wchar_t* lpwProcessName)
{
    HANDLE hProcessSnap = ::CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hProcessSnap == INVALID_HANDLE_VALUE)
    {
        perror(L"CreateToolhelp32Snapshot()");
        return -1;
    }

    DWORD dwPid = -1;

    do
    {
        PROCESSENTRY32W pe32 = { 0, };
        pe32.dwSize = sizeof(PROCESSENTRY32W);

        if (!::Process32FirstW(hProcessSnap, &pe32))
        {
            perror(L"Process32First()");
            break;
        }

        do
        {
            HANDLE hProcess = ::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pe32.th32ProcessID);
            if (!hProcess)
                continue;

            ::CloseHandle(hProcess);

            if (::wcscmp(lpwProcessName, pe32.szExeFile) == 0)
            {
                dwPid = pe32.th32ProcessID;
                break;
            }
        }
        while (::Process32NextW(hProcessSnap, &pe32));
    } 
    while (0);

    ::CloseHandle(hProcessSnap);
    return dwPid;
}


/*++



--*/
DWORD pwn::system::pidof(_In_ const std::wstring& name)
{
    return pidof(name.c_str());
}


/*++



--*/
BOOL PWNAPI pwn::system::is_elevated()
{
    HANDLE hProcess;
    int32_t dwCrssPid;
    
    dwCrssPid = pidof(CSRSS_PROCESS_NAME);
    if (dwCrssPid == -1)
    {
        auto msg = std::wstring(L"pidof('");
        msg += CSRSS_PROCESS_NAME;
        msg += L"')";
        perror(msg);
        return FALSE;
    }
    
    hProcess = ::OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwCrssPid);
    if (hProcess == NULL)
    {
        auto msg = std::wstring(L"OpenProcess('");
        msg += CSRSS_PROCESS_NAME;
        msg += L"')";
        perror(msg);
        return FALSE;
    }
    
    ::CloseHandle(hProcess);
    return TRUE;
}


