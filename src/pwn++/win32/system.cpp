#include "win32\system.hpp"

#include <tlhelp32.h>

#include <optional>
#include <stdexcept>

#include "handle.hpp"
#include "log.hpp"
#include "win32\nt.hpp"


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


namespace pwn::windows::system
{

auto
pagesize() -> u32
{
    SYSTEM_INFO siSysInfo = {
        {0},
    };
    ::GetSystemInfo(&siSysInfo);
    return siSysInfo.dwPageSize;
}


auto
pid(_In_ HANDLE hProcess) -> u32
{
    return ::GetProcessId(hProcess);
}


auto
ppid(_In_ u32 dwProcessId) -> std::optional<u32>
{
    auto hProcessSnap = pwn::utils::GenericHandle(::CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0));
    if ( !hProcessSnap )
    {
        perror(L"CreateToolhelp32Snapshot()");
        return std::nullopt;
    }

    PROCESSENTRY32 pe = {0};
    pe.dwSize         = sizeof(PROCESSENTRY32);
    i32 dwPpid        = -1;

    if ( ::Process32First(hProcessSnap.get(), &pe) )
    {
        do
        {
            if ( pe.th32ProcessID == dwProcessId )
            {
                dwPpid = pe.th32ParentProcessID;
                break;
            }
        } while ( ::Process32Next(hProcessSnap.get(), &pe) );
    }

    if ( dwPpid < 0 )
        return std::nullopt;

    return dwPpid;
}


auto
pidof(std::wstring_view const& targetProcessName) -> Result<std::vector<u32>>
{
    auto hProcessSnap = pwn::utils::GenericHandle(::CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0));
    if ( !hProcessSnap )
    {
        perror(L"CreateToolhelp32Snapshot()");
        return Err(ErrorType::Code::RuntimeError);
    }

    std::vector<u32> pids;

    do
    {
        PROCESSENTRY32W pe32 = {0};
        pe32.dwSize          = sizeof(PROCESSENTRY32W);

        if ( ::Process32FirstW(hProcessSnap.get(), &pe32) == 0 )
        {
            perror(L"Process32First()");
            break;
        }

        do
        {
            auto hProcess =
                pwn::utils::GenericHandle(::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pe32.th32ProcessID));
            if ( !hProcess )
            {
                continue;
            }

            const std::wstring currentProcessName {pe32.szExeFile};
            if ( targetProcessName == currentProcessName )
            {
                pids.push_back(pe32.th32ProcessID);
            }

        } while ( ::Process32Next(hProcessSnap.get(), &pe32) != 0 );
    } while ( false );

    return Ok(pids);
}


auto
computername() -> const std::wstring
{
    u32 dwBufLen                                 = MAX_COMPUTERNAME_LENGTH;
    wchar_t lpszBuf[MAX_COMPUTERNAME_LENGTH + 1] = {0};

    if ( ::GetComputerName(lpszBuf, (LPDWORD)&dwBufLen) == 0 )
    {
        // that case is weird enough it justifies throwing
        throw std::runtime_error("GetComputerName() failed");
    }
    return std::wstring(lpszBuf);
}


auto
username() -> const std::wstring
{
    wchar_t lpwsBuffer[UNLEN + 1] = {0};
    u32 dwBufferSize              = UNLEN + 1;
    if ( ::GetUserName((TCHAR*)lpwsBuffer, (LPDWORD)&dwBufferSize) == 0 )
    {
        // that case is weird enough it justifies throwing
        throw std::runtime_error("GetUserName() failed");
    }

    static auto username = std::wstring {lpwsBuffer};
    return username;
}


auto
modulename(_In_opt_ HMODULE hModule) -> std::optional<std::wstring>
{
    wchar_t lpwsBuffer[MAX_PATH] = {0};
    if ( ::GetModuleFileName(hModule, lpwsBuffer, MAX_PATH) == 0u )
    {
        perror("GetModuleFileName()");
        return std::nullopt;
    }
    static auto module_filename = std::wstring {lpwsBuffer};
    return module_filename;
}


auto
filename() -> std::optional<std::wstring>
{
    return modulename(nullptr);
}

} // namespace pwn::windows::system
