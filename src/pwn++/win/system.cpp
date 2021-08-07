#include "system.hpp"
#include "log.hpp"
#include "nt.hpp"
#include "handle.hpp"

#include <tlhelp32.h>
#include <stdexcept>


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


auto pwn::system::pagesize() -> DWORD
{
    SYSTEM_INFO siSysInfo = { {0}, };
    ::GetSystemInfo(&siSysInfo);
    return siSysInfo.dwPageSize;
}



auto pwn::system::pid(_In_ HANDLE hProcess) -> DWORD
{
    return ::GetProcessId(hProcess);
}



auto pwn::system::ppid(_In_ DWORD dwProcessId) -> DWORD
{
    auto hProcessSnap = pwn::utils::GenericHandle(::CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0));
    if (!hProcessSnap)
    {
        perror(L"CreateToolhelp32Snapshot()");
        return -1;
    }

    PROCESSENTRY32 pe = { 0, };
    pe.dwSize = sizeof(PROCESSENTRY32);
    i32 dwPpid = -1;

    if (Process32First(hProcessSnap.get(), &pe))
    {
        do
        {
            if (pe.th32ProcessID == dwProcessId)
            {
                dwPpid = pe.th32ParentProcessID;
                break;
            }
        }
        while (Process32Next(hProcessSnap.get(), &pe));
    }

    return dwPpid;
}



/*++

Description:

    Look up for a process name with the given argument, and return the PID of the first instance

Arguments:

    - lpwProcessName an LPWSTR of the name of the process to find

Returns:

    the PID of the first process if found, -1 if failure

 --*/
auto PWNAPI pwn::system::pidof(_In_ const std::wstring& name) -> DWORD
{
    auto hProcessSnap = pwn::utils::GenericHandle( ::CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) );
    if (!hProcessSnap)
    {
        perror(L"CreateToolhelp32Snapshot()");
        return -1;
    }

    DWORD dwPid = -1;

    do
    {
        PROCESSENTRY32W pe32 = { 0, };
        pe32.dwSize = sizeof(PROCESSENTRY32W);

        if (::Process32FirstW(hProcessSnap.get(), &pe32) == 0)
        {
            perror(L"Process32First()");
            break;
        }

        do
        {
            HANDLE hProcess = ::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pe32.th32ProcessID);
            if (hProcess == nullptr) {
                continue;
}

            ::CloseHandle(hProcess);

            if (::wcscmp(name.c_str(), pe32.szExeFile) == 0)
            {
                dwPid = pe32.th32ProcessID;
                break;
            }
        }
        while (::Process32NextW(hProcessSnap.get(), &pe32) != 0);
    }
    while (false);

    return dwPid;
}




auto pwn::system::computername() -> const std::wstring
{
    DWORD dwBufLen = MAX_COMPUTERNAME_LENGTH;
    WCHAR lpszBuf[MAX_COMPUTERNAME_LENGTH + 1] = { 0, };
    if(::GetComputerName(lpszBuf, &dwBufLen) == 0) {
        throw std::runtime_error("GetComputerName() failed");
}
    return std::wstring(lpszBuf);
}



auto pwn::system::username() -> const std::wstring
{
    wchar_t lpwsBuffer[UNLEN + 1];
    DWORD dwBufferSize = UNLEN + 1;
    if(::GetUserName((TCHAR*)lpwsBuffer, &dwBufferSize) == 0) {
        throw std::runtime_error("GetUserName() failed");
}
    static auto username = std::wstring{ lpwsBuffer };
    return username;
}


auto pwn::system::modulename(_In_opt_ HMODULE hModule) -> const std::wstring
{
    wchar_t lpwsBuffer[MAX_PATH]{ 0 };
    if (::GetModuleFileName(hModule, lpwsBuffer, MAX_PATH) == 0u) {
        throw std::runtime_error("GetModuleFileName() failed");
}
    static auto module_filename = std::wstring{ lpwsBuffer };
    return module_filename;
}


auto pwn::system::filename() -> const std::wstring
{
    return pwn::system::modulename(nullptr);
}

