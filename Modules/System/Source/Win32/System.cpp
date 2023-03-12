#include "Win32/System.hpp"

#include <tlhelp32.h>

#include "Handle.hpp"
#include "Log.hpp"


#define SYSTEM_PROCESS_NAME L"System"
#define LSASS_PROCESS_NAME L"lsass.exe"
#define CSRSS_PROCESS_NAME L"csrss.exe"
#define CALC_PROCESS_NAME L"calc.exe"
#define CMD_PROCESS_NAME L"cmd.exe"

#define WINDOWS_SYSTEM32_PATH L"\\SystemRoot\\system32\\"
#define CALC_PATH WINDOWS_SYSTEM32_PATH CALC_PROCESS_NAME
#define CMD_PATH WINDOWS_SYSTEM32_PATH CMD_PROCESS_NAME
#define KERNEL_PROCESS_NAME WINDOWS_SYSTEM32_PATH L"ntoskrnl.exe"

#ifndef UNLEN
#define UNLEN 256
#endif // !UNLEN


namespace pwn::System
{

auto
System::PageSize() -> u32
{
    SYSTEM_INFO siSysInfo {};
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
    auto hProcessSnap = UniqueHandle {::CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)};
    if ( !hProcessSnap )
    {
        Log::perror(L"CreateToolhelp32Snapshot()");
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
    auto hProcessSnap = UniqueHandle(::CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0));
    if ( !hProcessSnap )
    {
        Log::perror(L"CreateToolhelp32Snapshot()");
        return Err(ErrorCode::ExternalApiCallFailed);
    }

    std::vector<u32> pids;

    PROCESSENTRY32W pe32 = {0};
    pe32.dwSize          = sizeof(PROCESSENTRY32W);

    if ( ::Process32FirstW(hProcessSnap.get(), &pe32) == 0 )
    {
        Log::perror(L"Process32First()");
        return Err(ErrorCode::ExternalApiCallFailed);
    }

    std::wstring targetProcessName = std::wstring {ProcessName};
    std::transform(targetProcessName.begin(), targetProcessName.end(), targetProcessName.begin(), ::towlower);

    do
    {
        auto hProcess = UniqueHandle {::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pe32.th32ProcessID)};
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


Result<std::wstring>
System::UserName()
{
    wchar_t lpwsBuffer[UNLEN + 1] = {0};
    u32 dwBufferSize              = UNLEN + 1;
    if ( ::GetUserName((TCHAR*)lpwsBuffer, (LPDWORD)&dwBufferSize) == 0 )
    {
        Log::perror(L"GetUserName()");
        return Err(ErrorCode::ExternalApiCallFailed);
    }

    static auto username = std::wstring {lpwsBuffer};
    return username;
}


Result<std::wstring>
System::ModuleName(HMODULE hModule)
{
    wchar_t lpwsBuffer[MAX_PATH] = {0};
    if ( ::GetModuleFileName(hModule, lpwsBuffer, MAX_PATH) == 0u )
    {
        Log::perror(L"GetModuleFileName()");
        return Err(ErrorCode::ExternalApiCallFailed);
    }

    static auto module_filename = std::wstring {lpwsBuffer};
    return module_filename;
}


Result<std::wstring>
System::FileName()
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
        Log::perror(L"LocalAlloc()");
        return Err(ErrorCode::AllocationError);
    }

    do
    {
        Status = ::NtQuerySystemInformation(SystemInformationClass, Buffer, Size, &ReturnLength);
        if ( NT_SUCCESS(Status) )
        {
            return Ok(Buffer);
        }

        if ( Status != STATUS_INFO_LENGTH_MISMATCH )
        {
            Log::ntperror(L"NtQueryInformationThread()", Status);
            break;
        }

        HLOCAL NewBuffer = ::LocalReAlloc(Buffer, ReturnLength, LMEM_MOVEABLE | LMEM_ZEROINIT);
        if ( NewBuffer )
        {
            Size   = ReturnLength;
            Buffer = NewBuffer;
            continue;
        }

        Log::perror(L"LocalReAlloc() failed");
        break;

    } while ( true );

    ::LocalFree(Buffer);
    return Err(ErrorCode::ExternalApiCallFailed);
}

Result<std::tuple<u8, u8, u8, u8, u8>>
System::ProcessorCount()
{
    DWORD size                = 0;
    u8 ProcessorCount         = 0;
    u8 LogicalProcessorCount  = 0;
    u8 ProcessorCacheCount[3] = {0};

    ::GetLogicalProcessorInformation(nullptr, &size);
    if ( ::GetLastError() != ERROR_INSUFFICIENT_BUFFER )
    {
        Log::perror(L"GetLogicalProcessorInformation()");
        return Err(ErrorCode::ExternalApiCallFailed);
    }

    const usize NbEntries = size / sizeof(SYSTEM_LOGICAL_PROCESSOR_INFORMATION);
    auto ProcessorInfo    = std::make_unique<SYSTEM_LOGICAL_PROCESSOR_INFORMATION[]>(NbEntries);
    if ( ::GetLogicalProcessorInformation(ProcessorInfo.get(), &size) == FALSE )
    {
        Log::perror(L"GetLogicalProcessorInformation()");
        return Err(ErrorCode::ExternalApiCallFailed);
    }

    std::for_each(
        std::next(ProcessorInfo.get(), 0),
        std::next(ProcessorInfo.get(), NbEntries),
        [&LogicalProcessorCount, &ProcessorCount, &ProcessorCacheCount](SYSTEM_LOGICAL_PROCESSOR_INFORMATION const& p)
        {
            if ( p.Relationship == RelationProcessorCore )
            {
                ProcessorCount++;
                LogicalProcessorCount += std::bitset<32>(p.ProcessorMask).count();
            }

            if ( p.Relationship == RelationCache )
            {
                ProcessorCacheCount[(p.Cache.Level - 1)]++;
            }
        });

    return std::make_tuple(
        ProcessorCount,
        LogicalProcessorCount,
        ProcessorCacheCount[0],
        ProcessorCacheCount[1],
        ProcessorCacheCount[2]);
}


Result<std::vector<RTL_PROCESS_MODULE_INFORMATION>>
System::Modules()
{
    auto res = Query<RTL_PROCESS_MODULES>(SystemModuleInformation);
    if ( Failed(res) )
    {
        return Err(ErrorCode::ExternalApiCallFailed);
    }

    std::vector<RTL_PROCESS_MODULE_INFORMATION> Mods;
    auto ModInfo = Value(res);

    std::for_each(
        std::next(ModInfo->Modules, 0),
        std::next(ModInfo->Modules, ModInfo->NumberOfModules),
        [&Mods](auto const& M)
        {
            Mods.push_back(M);
        });

    return Mods;
}


Result<std::vector<SYSTEM_HANDLE_TABLE_ENTRY_INFO>>
System::Handles()
{
    auto res = Query<SYSTEM_HANDLE_INFORMATION>(SystemHandleInformation);
    if ( Failed(res) )
    {
        return Err(ErrorCode::ExternalApiCallFailed);
    }

    std::vector<SYSTEM_HANDLE_TABLE_ENTRY_INFO> SystemHandles;
    auto HandleInfo = Value(res);

    std::for_each(
        std::next(HandleInfo->Handles, 0),
        std::next(HandleInfo->Handles, HandleInfo->NumberOfHandles),
        [&SystemHandles](auto const& H)
        {
            SystemHandles.push_back(H);
        });

    return SystemHandles;
}

} // namespace System
