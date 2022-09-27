#include "win32\system.hpp"

#include <tlhelp32.h>

#include <algorithm>
#include <cwctype>
#include <iostream>
#include <optional>
#include <stdexcept>
#include <tuple>

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


EXTERN_C_START


NTSYSAPI NTSTATUS
RtlGetVersion(POSVERSIONINFOEXW lpVersionInformation);

EXTERN_C_END

namespace pwn::windows
{

auto
System::PageSize() -> u32
{
    SYSTEM_INFO siSysInfo = {
        {0},
    };
    ::GetSystemInfo(&siSysInfo);
    return siSysInfo.dwPageSize;
}


auto
System::ProcessId(_In_ HANDLE hProcess) -> u32
{
    return (hProcess == GetCurrentProcess()) ? ::GetCurrentProcessId() : ::GetProcessId(hProcess);
}


std::optional<u32>
System::ParentProcessId(const u32 dwProcessId)
{
    auto hProcessSnap = pwn::UniqueHandle {::CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)};
    if ( !hProcessSnap )
    {
        log::perror(L"CreateToolhelp32Snapshot()");
        return std::nullopt;
    }

    PROCESSENTRY32 pe = {0};
    pe.dwSize         = sizeof(PROCESSENTRY32);

    if ( ::Process32First(hProcessSnap.get(), &pe) )
    {
        do
        {
            if ( pe.th32ProcessID == dwProcessId )
            {
                return pe.th32ParentProcessID;
            }
        } while ( ::Process32NextW(hProcessSnap.get(), &pe) );
    }

    return std::nullopt;
}


auto
System::PidOf(std::wstring_view const& ProcessName) -> Result<std::vector<u32>>
{
    auto hProcessSnap = pwn::UniqueHandle(::CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0));
    if ( !hProcessSnap )
    {
        log::perror(L"CreateToolhelp32Snapshot()");
        return Err(ErrorCode::ExternalApiCallFailed);
    }

    std::vector<u32> pids;

    PROCESSENTRY32W pe32 = {0};
    pe32.dwSize          = sizeof(PROCESSENTRY32W);

    if ( ::Process32FirstW(hProcessSnap.get(), &pe32) == 0 )
    {
        log::perror(L"Process32First()");
        return Err(ErrorCode::ExternalApiCallFailed);
    }

    std::wstring targetProcessName = std::wstring {ProcessName};
    std::transform(targetProcessName.begin(), targetProcessName.end(), targetProcessName.begin(), ::towlower);

    do
    {
        auto hProcess = pwn::UniqueHandle {::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pe32.th32ProcessID)};
        if ( !hProcess )
        {
            continue;
        }

        std::wstring currentProcessName {pe32.szExeFile};
        std::transform(currentProcessName.begin(), currentProcessName.end(), currentProcessName.begin(), ::towlower);

        if ( targetProcessName == currentProcessName )
        {
            pids.push_back(pe32.th32ProcessID);
        }

    } while ( ::Process32NextW(hProcessSnap.get(), &pe32) != 0 );

    return Ok(pids);
}


auto
System::ComputerName() -> const std::wstring
{
    u32 dwBufLen                                 = MAX_COMPUTERNAME_LENGTH;
    wchar_t lpszBuf[MAX_COMPUTERNAME_LENGTH + 1] = {0};

    if ( ::GetComputerName(lpszBuf, (LPDWORD)&dwBufLen) == 0 )
    {
        // that case is weird enough it justifies throwing
        throw std::runtime_error("GetComputerName() failed");
    }
    return std::wstring {lpszBuf};
}


auto
System::UserName() -> const std::wstring
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
System::ModuleName(_In_opt_ HMODULE hModule) -> std::optional<std::wstring>
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
System::FileName() -> std::optional<std::wstring>
{
    return ModuleName(nullptr);
}

std::tuple<u32, u32, u32>
System::WindowsVersion()
{
    OSVERSIONINFOEXW VersionInformation;
    VersionInformation.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEXW);

    NTSTATUS Status = ::RtlGetVersion(&VersionInformation);
    if ( !NT_SUCCESS(Status) )
    {
        throw std::runtime_error("RtlGetVersion() failed");
    }

    return {VersionInformation.dwMajorVersion, VersionInformation.dwMinorVersion, VersionInformation.dwBuildNumber};
}

Result<PVOID>
System::QueryInternal(const SYSTEM_INFORMATION_CLASS SystemInformationClass, const usize InitialSize)
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
        Status = ::NtQuerySystemInformation(SystemInformationClass, Buffer, Size, &ReturnLength);
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

        log::ntperror(L"NtQueryInformationThread()", Status);
        return Err(ErrorCode::PermissionDenied);

    } while ( true );

    return Ok(Buffer);
}

} // namespace pwn::windows
