#include "Win32/Service.hpp"

#include <chrono>
#include <ranges>
#include <stdexcept>

#include "Log.hpp"


namespace pwn::Services
{

Result<DWORD>
Service::Create(std::wstring_view const& ServiceName, std::wstring_view const& ServicePath, ServiceType SvcType)
{
    auto hManager = ServiceHandle {::OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ALL_ACCESS)};
    if ( !hManager )
    {
        Log::perror(L"OpenSCManager()");
        return Err(ErrorCode::ExternalApiCallFailed);
    }

    auto hService = ServiceHandle {::CreateServiceW(
        hManager.get(),
        (LPCWSTR)ServiceName.data(),
        nullptr,
        SERVICE_ALL_ACCESS,
        static_cast<std::underlying_type<ServiceType>::type>(SvcType),
        SERVICE_DEMAND_START,
        SERVICE_ERROR_IGNORE,
        (LPCWSTR)ServicePath.data(),
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr)};
    if ( !hService )
    {
        Log::perror(L"CreateService()");
        return Err(ErrorCode::ExternalApiCallFailed);
    }

    return Ok((DWORD)ERROR_SUCCESS);
}


Result<DWORD>
Service::Start(std::wstring_view const& ServiceName)
{

    auto hManager = ServiceHandle {::OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ALL_ACCESS)};
    if ( !hManager )
    {
        Log::perror(L"OpenSCManager()");
        return Err(ErrorCode::ExternalApiCallFailed);
    }


    auto hService = ServiceHandle {::OpenServiceW(hManager.get(), ServiceName.data(), SERVICE_START)};
    if ( !hService )
    {
        Log::perror(L"OpenService()");
        return Err(ErrorCode::ExternalApiCallFailed);
    }


    if ( ::StartServiceW(hService.get(), 0, nullptr) == 0 )
    {
        Log::perror(L"StartService()");
        return Err(ErrorCode::ExternalApiCallFailed);
    }

    return Ok((DWORD)ERROR_SUCCESS);
}


Result<DWORD>
Service::Stop(std::wstring_view const& ServiceName, const u32 Timeout)
{
    DWORD dwResult = ERROR_SUCCESS;
    DWORD dwBytes  = 0;

    do
    {
        auto hManager = ServiceHandle {::OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ALL_ACCESS)};
        if ( !hManager )
        {
            Log::perror(L"OpenSCManager()");
            dwResult = ::GetLastError();
            break;
        }

        auto hService = ServiceHandle {
            ::OpenServiceW(hManager.get(), (LPCWSTR)ServiceName.data(), SERVICE_STOP | SERVICE_QUERY_STATUS)};
        if ( !hService )
        {
            Log::perror(L"OpenService()");
            dwResult = ::GetLastError();
            break;
        }

        SERVICE_STATUS_PROCESS Status = {0};
        if ( ::ControlService(hService.get(), SERVICE_CONTROL_STOP, (SERVICE_STATUS*)&Status) == 0 )
        {
            Log::perror(L"ControlService()");
            dwResult = ::GetLastError();
            break;
        }

        const auto start = std::chrono::system_clock::now();


        //
        // Check that the service got correctly stopped
        //
        while ( true )
        {
            if ( ::QueryServiceStatusEx(
                     hService.get(),
                     SC_STATUS_PROCESS_INFO,
                     (LPBYTE)&Status,
                     sizeof(SERVICE_STATUS_PROCESS),
                     &dwBytes) == 0 )
            {
                Log::perror(L"QueryServiceStatusEx()");
                break;
            }

            if ( Status.dwCurrentState == SERVICE_STOPPED )
            {
                dwResult = ERROR_SUCCESS;
                break;
            }

            const auto end                           = std::chrono::system_clock::now();
            const std::chrono::duration<double> diff = end - start;
            if ( diff.count() > Timeout )
            {
                Log::perror(L"StopService()");
                dwResult = ERROR_TIMEOUT;
                break;
            }

            ::Sleep(Status.dwWaitHint);
        }
    } while ( false );

    ::SetLastError(dwResult);
    return Ok(dwResult);
}


Result<DWORD>
Service::Destroy(std::wstring_view const& ServiceName)
{
    DWORD dwResult = ERROR_SUCCESS;

    do
    {
        auto hManager = ServiceHandle {::OpenSCManager(nullptr, nullptr, SC_MANAGER_ALL_ACCESS)};
        if ( !hManager )
        {
            Log::perror(L"StartService()");
            dwResult = ::GetLastError();
            break;
        }

        auto hService = ServiceHandle {::OpenService(hManager.get(), ServiceName.data(), DELETE)};
        if ( !hService )
        {
            Log::perror(L"OpenService()");
            dwResult = ::GetLastError();
            break;
        }

        if ( ::DeleteService(hService.get()) == 0 )
        {
            Log::perror(L"DeleteService()");
            dwResult = ::GetLastError();
            break;
        }
    } while ( false );

    ::SetLastError(dwResult);
    return Ok(dwResult);
}


Result<std::vector<ServiceInfo>>
Service::List()
{
    std::vector<ServiceInfo> services;
    DWORD dwResult = ERROR_SUCCESS;

    do
    {
        auto hManager = ServiceHandle(::OpenSCManager(nullptr, nullptr, SC_MANAGER_ENUMERATE_SERVICE));
        if ( !hManager )
        {
            Log::perror(L"StartService()");
            dwResult = ::GetLastError();
            break;
        }

        //
        // Get the structure size
        //

        u32 dwBufferSize        = 0;
        u32 dwServiceEntryCount = 0;
        u32 dwResumeHandle      = 0;

        BOOL bRes = ::EnumServicesStatusEx(
            hManager.get(),
            SC_ENUM_PROCESS_INFO,
            SERVICE_KERNEL_DRIVER | SERVICE_FILE_SYSTEM_DRIVER | SERVICE_WIN32_OWN_PROCESS |
                SERVICE_WIN32_SHARE_PROCESS,
            SERVICE_STATE_ALL,
            nullptr,
            0,
            (LPDWORD)&dwBufferSize,
            (LPDWORD)&dwServiceEntryCount,
            (LPDWORD)&dwResumeHandle,
            nullptr);

        if ( (bRes == 0) && ::GetLastError() != ERROR_MORE_DATA )
        {
            Log::perror(L"EnumServicesStatusEx(1)");
            dwResult = ::GetLastError();
            break;
        }

        dbg(L"BufSz={},EntryCnt={},ResumeHandle={},sizeof={}",
            dwBufferSize,
            dwServiceEntryCount,
            dwResumeHandle,
            sizeof(ENUM_SERVICE_STATUS_PROCESS));
        auto Buffer = std::make_unique<ENUM_SERVICE_STATUS_PROCESS[]>(dwBufferSize);

        if ( ::EnumServicesStatusExW(
                 hManager.get(),
                 SC_ENUM_PROCESS_INFO,
                 SERVICE_KERNEL_DRIVER | SERVICE_FILE_SYSTEM_DRIVER | SERVICE_WIN32_OWN_PROCESS |
                     SERVICE_WIN32_SHARE_PROCESS,
                 SERVICE_STATE_ALL,
                 reinterpret_cast<LPBYTE>(Buffer.get()),
                 dwBufferSize,
                 (LPDWORD)&dwBufferSize,
                 (LPDWORD)&dwServiceEntryCount,
                 (LPDWORD)&dwResumeHandle,
                 nullptr) == 0 )
        {
            Log::perror(L"EnumServicesStatusEx(2)");
            dwResult = ::GetLastError();
            break;
        }

        dbg(L"BufSz={}, EntryCnt={}, ResumeHandle={}, sizeof={}",
            dwBufferSize,
            dwServiceEntryCount,
            dwResumeHandle,
            sizeof(ENUM_SERVICE_STATUS_PROCESS));

        for ( u32 i : std::views::iota(0u, dwServiceEntryCount) )
        {
            auto service        = ServiceInfo {};
            service.Name        = Buffer[i].lpServiceName;
            service.DisplayName = Buffer[i].lpDisplayName;
            service.Status      = Buffer[i].ServiceStatusProcess.dwCurrentState;
            service.Type        = Buffer[i].ServiceStatusProcess.dwServiceType;
            service.ProcessId   = Buffer[i].ServiceStatusProcess.dwProcessId;
            service.Path        = std::nullopt;

            auto hService = ServiceHandle {::OpenService(hManager.get(), service.Name.data(), SERVICE_QUERY_CONFIG)};
            if ( hService )
            {
                usize BufferSize = sizeof(QUERY_SERVICE_CONFIG);

                while ( true )
                {
                    std::unique_ptr<u8[]> Buffer = std::make_unique<u8[]>(BufferSize);
                    QUERY_SERVICE_CONFIG* cfg    = reinterpret_cast<QUERY_SERVICE_CONFIG*>(Buffer.get());
                    u32 needed                   = 0;
                    if ( ::QueryServiceConfigW(hService.get(), cfg, BufferSize, (LPDWORD)&needed) == TRUE )
                    {

                        service.Path = std::make_optional(std::filesystem::path {cfg->lpBinaryPathName});
                        break;
                    }

                    if ( ::GetLastError() != ERROR_INSUFFICIENT_BUFFER )
                    {
                        Log::perror(L"QueryServiceConfigW()");
                        break;
                    }

                    BufferSize = needed;
                }
            }
            services.push_back(service);
        }

    } while ( false );

    if ( dwResult != ERROR_SUCCESS )
    {
        ::SetLastError(dwResult);
        return Err(ErrorCode::ServiceError);
    }

    return Ok(services);
}


Result<bool>
Service::IsRunning(const std::wstring_view& ServiceName)
{
    DWORD dwResult = ERROR_SUCCESS;
    bool bRes      = false;

    do
    {
        auto hManager = ServiceHandle(::OpenSCManager(nullptr, nullptr, SC_MANAGER_ALL_ACCESS));
        if ( !hManager )
        {
            Log::perror(L"OpenSCManager()");
            dwResult = ::GetLastError();
            break;
        }

        auto hService = ServiceHandle(::OpenService(hManager.get(), ServiceName.data(), SERVICE_QUERY_STATUS));
        if ( !hService )
        {
            Log::perror(L"OpenService()");
            dwResult = ::GetLastError();
            break;
        }

        DWORD dwBytes                 = 0;
        SERVICE_STATUS_PROCESS Status = {0};
        if ( ::QueryServiceStatusEx(
                 hService.get(),
                 SC_STATUS_PROCESS_INFO,
                 (LPBYTE)&Status,
                 sizeof(SERVICE_STATUS_PROCESS),
                 &dwBytes) == 0 )
        {
            Log::perror(L"QueryServiceStatusEx()");
            break;
        }

        dwResult = ERROR_SUCCESS;

        if ( Status.dwCurrentState == SERVICE_RUNNING )
        {
            bRes = true;
        }
    } while ( false );

    if ( dwResult != ERROR_SUCCESS )
    {
        ::SetLastError(dwResult);
        return Err(ErrorCode::ServiceError);
    }

    return Ok(bRes);
}

} // namespace Services
