#include "Win32/System.hpp"

#include <bitset>
#include <experimental/generator>
#include <iostream>
#include <ranges>
#include <span>
#include <vector>

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
PageSize() -> u32
{
    static u32 __page_size {};
    if ( !__page_size ) [[unlikely]]
    {
        SYSTEM_INFO siSysInfo {};
        ::GetSystemInfo(&siSysInfo);
        __page_size = siSysInfo.dwPageSize;
    }
    return __page_size;
}


auto
ProcessId(_In_ HANDLE hProcess) -> u32
{
    return (hProcess == GetCurrentProcess()) ? ::GetCurrentProcessId() : ::GetProcessId(hProcess);
}

auto
ComputerName() -> const std::wstring
{
    static std::wstring computername {};
    if ( computername.empty() )
    {
        u32 dwBufLen                                 = MAX_COMPUTERNAME_LENGTH;
        wchar_t lpszBuf[MAX_COMPUTERNAME_LENGTH + 1] = {0};
        if ( ::GetComputerNameW(lpszBuf, (LPDWORD)&dwBufLen) == FALSE )
        {
            throw std::runtime_error("GetComputerName() failed");
        }

        computername = std::wstring {lpszBuf, dwBufLen};
    }
    return computername;
}


Result<std::wstring>
UserName()
{
    static std::wstring username {};
    if ( username.empty() )
    {
        u32 dwBufferSize              = UNLEN + 1;
        wchar_t lpwsBuffer[UNLEN + 1] = {0};
        if ( ::GetUserNameW((WCHAR*)lpwsBuffer, (LPDWORD)&dwBufferSize) == 0 )
        {
            Log::perror(L"GetUserName()");
            return Err(Error::ExternalApiCallFailed);
        }

        username = std::wstring {lpwsBuffer, dwBufferSize};
    }
    return username;
}


Result<std::wstring>
ModuleName(HMODULE hModule)
{
    wchar_t lpwsBuffer[MAX_PATH] = {0};
    if ( ::GetModuleFileName(hModule, lpwsBuffer, MAX_PATH) == 0u )
    {
        Log::perror(L"GetModuleFileName()");
        return Err(Error::ExternalApiCallFailed);
    }

    static auto module_filename = std::wstring {lpwsBuffer};
    return module_filename;
}


Result<std::wstring>
FileName()
{
    return ModuleName(nullptr);
}

std::tuple<u32, u32, u32>
WindowsVersion()
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

Result<std::unique_ptr<u8[]>>
details::QueryInternal(const SYSTEM_INFORMATION_CLASS SystemInformationClass, const usize InitialSize)
{
    usize Size                   = InitialSize;
    ULONG ReturnLength           = 0;
    NTSTATUS Status              = STATUS_SUCCESS;
    std::unique_ptr<u8[]> Buffer = nullptr;

    do
    {

        Status = ::NtQuerySystemInformation(SystemInformationClass, Buffer.get(), Size, &ReturnLength);
        if ( NT_SUCCESS(Status) )
        {
            return Ok(Buffer);
        }

        if ( Status != STATUS_INFO_LENGTH_MISMATCH )
        {
            Log::ntperror(L"NtQueryInformationThread()", Status);
            break;
        }

        Buffer = std::make_unique<u8[]>(ReturnLength);
        continue;

    } while ( true );

    return Err(Error::ExternalApiCallFailed);
}

Result<std::tuple<u8, u8, u8, u8, u8>>
ProcessorCount()
{
    DWORD size                = 0;
    u8 ProcessorCount         = 0;
    u8 LogicalProcessorCount  = 0;
    u8 ProcessorCacheCount[3] = {0};

    ::GetLogicalProcessorInformation(nullptr, &size);
    if ( ::GetLastError() != ERROR_INSUFFICIENT_BUFFER )
    {
        Log::perror(L"GetLogicalProcessorInformation()");
        return Err(Error::ExternalApiCallFailed);
    }

    const usize NbEntries = size / sizeof(SYSTEM_LOGICAL_PROCESSOR_INFORMATION);
    auto ProcessorInfo    = std::make_unique<SYSTEM_LOGICAL_PROCESSOR_INFORMATION[]>(NbEntries);
    if ( ::GetLogicalProcessorInformation(ProcessorInfo.get(), &size) == FALSE )
    {
        Log::perror(L"GetLogicalProcessorInformation()");
        return Err(Error::ExternalApiCallFailed);
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
Modules()
{
    auto res = Query<RTL_PROCESS_MODULES>(SystemModuleInformation);
    if ( Failed(res) )
    {
        return Err(Error::ExternalApiCallFailed);
    }

    std::vector<RTL_PROCESS_MODULE_INFORMATION> Mods;
    auto ModInfo = std::move(Value(res));

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
Handles()
{
    auto res = Query<SYSTEM_HANDLE_INFORMATION>(SystemHandleInformation);
    if ( Failed(res) )
    {
        return Err(Error::ExternalApiCallFailed);
    }

    std::vector<SYSTEM_HANDLE_TABLE_ENTRY_INFO> SystemHandles;
    auto HandleInfo = std::move(Value(res));

    std::for_each(
        std::next(HandleInfo->Handles, 0),
        std::next(HandleInfo->Handles, HandleInfo->NumberOfHandles),
        [&SystemHandles](auto const& H)
        {
            SystemHandles.push_back(H);
        });

    return SystemHandles;
}


std::experimental::generator<const SYSTEM_PROCESS_INFORMATION*>
QuerySystemProcessInformation()
{
    auto res = Query<SYSTEM_PROCESS_INFORMATION>(SYSTEM_INFORMATION_CLASS::SystemProcessInformation);
    if ( Failed(res) )
    {
        co_yield nullptr;
    }

    auto spProcessInfo = std::move(Value(res));
    for ( auto curProcInfo = spProcessInfo.get(); curProcInfo->NextEntryOffset;
          curProcInfo =
              reinterpret_cast<PSYSTEM_PROCESS_INFORMATION>((uptr)curProcInfo + curProcInfo->NextEntryOffset) )
    {
        co_yield curProcInfo;
    }
}


Result<std::vector<std::tuple<u32, u32>>>
Threads()
{
    auto res = Query<SYSTEM_PROCESS_INFORMATION>(SYSTEM_INFORMATION_CLASS::SystemProcessInformation);
    if ( Failed(res) )
    {
        return Err(Error::ExternalApiCallFailed);
    }

    auto IsValid = [](auto si)
    {
        return si != nullptr;
    };

    std::vector<std::tuple<u32, u32>> tids {};
    for ( auto curProcInfo : QuerySystemProcessInformation() | std::views::take_while(IsValid) )
    {
        std::for_each(
            std::next(curProcInfo->Threads, 0),
            std::next(curProcInfo->Threads, curProcInfo->NumberOfThreads),
            [&tids](SYSTEM_THREAD_INFORMATION const& t)
            {
                tids.push_back({
                    HandleToUlong(t.ClientId.UniqueProcess),
                    HandleToUlong(t.ClientId.UniqueThread),
                });
            });
    }

    return Ok(tids);
}


auto
ParentProcessId(const u32 dwProcessId) -> Result<u32>
{
    auto IsValid = [](auto si)
    {
        return si != nullptr;
    };

    auto MatchesProcessId = [dwProcessId](auto si)
    {
        return HandleToUlong(si->UniqueProcessId) == dwProcessId;
    };

    for ( auto curProcInfo :
          QuerySystemProcessInformation() | std::views::take_while(IsValid) | std::views::filter(MatchesProcessId) )
    {
        return HandleToUlong(curProcInfo->InheritedFromUniqueProcessId);
    }

    return Err(Error::NotFound);
}


auto
PidOf(std::wstring_view const ProcessName) -> Result<std::vector<u32>>
{
    const std::wstring targetProcessName = [&ProcessName]()
    {
        std::wstring str {ProcessName};
        std::transform(str.begin(), str.end(), str.begin(), ::towlower);
        return str;
    }();

    std::vector<u32> pids {};

    auto IsValid = [](auto si)
    {
        return si != nullptr;
    };

    auto MatchesImageName = [&targetProcessName](auto si)
    {
        const std::wstring curProcName = [si]()
        {
            std::wstring str {si->ImageName.Buffer, si->ImageName.Length / sizeof(wchar_t)};
            std::transform(str.begin(), str.end(), str.begin(), ::towlower);
            return str;
        }();
        return curProcName == targetProcessName;
    };

    for ( auto curProcInfo :
          QuerySystemProcessInformation() | std::views::take_while(IsValid) | std::views::filter(MatchesImageName) )
    {
        pids.push_back(HandleToULong(curProcInfo->UniqueProcessId));
    }

    return pids;
}

} // namespace pwn::System
