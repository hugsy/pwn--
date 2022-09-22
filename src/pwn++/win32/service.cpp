#include "service.hpp"

#include <chrono>
#include <stdexcept>

#include "log.hpp"

using namespace pwn::log;


namespace pwn::windows::service
{

auto
create(std::string_view const& ServiceName, std::string_view const& ServicePath) -> Result<DWORD>
{
    DWORD dwResult = ERROR_SUCCESS;

    do
    {
        auto hManager = ServiceHandle {::OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ALL_ACCESS)};
        if ( !hManager )
        {
            perror(L"OpenSCManager()");
            dwResult = ::GetLastError();
            break;
        }

        auto hService = ServiceHandle {::CreateServiceW(
            hManager.get(),
            (LPCWSTR)ServiceName.data(),
            nullptr,
            SERVICE_ALL_ACCESS,
            SERVICE_WIN32_OWN_PROCESS,
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
            perror(L"CreateService()");
            dwResult = ::GetLastError();
            break;
        }
    } while ( false );

    ::SetLastError(dwResult);
    return Ok(dwResult);
}


auto
start(std::wstring_view const& ServiceName) -> Result<DWORD>
{
    DWORD dwResult = ERROR_SUCCESS;

    SC_HANDLE t = ::OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ALL_ACCESS);
    t->unused;

    do
    {
        auto hManager = ServiceHandle {::OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ALL_ACCESS)};
        if ( !hManager )
        {
            perror(L"OpenSCManager()");
            dwResult = ::GetLastError();
            break;
        }


        auto hService = ServiceHandle {::OpenServiceW(hManager.get(), ServiceName.data(), SERVICE_START)};
        if ( !hService )
        {
            perror(L"OpenService()");
            dwResult = ::GetLastError();
            break;
        }


        if ( ::StartServiceW(hService.get(), 0, nullptr) == 0 )
        {
            perror(L"StartService()");
            dwResult = ::GetLastError();
            break;
        }

    } while ( false );

    ::SetLastError(dwResult);
    return Ok(dwResult);
}


auto
stop(std::string_view const& ServiceName, const DWORD Timeout) -> Result<DWORD>
{
    DWORD dwResult = ERROR_SUCCESS;
    DWORD dwBytes  = 0;

    do
    {
        auto hManager = ServiceHandle {::OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ALL_ACCESS)};
        if ( !hManager )
        {
            perror(L"OpenSCManager()");
            dwResult = ::GetLastError();
            break;
        }

        auto hService = ServiceHandle {
            ::OpenServiceW(hManager.get(), (LPCWSTR)ServiceName.data(), SERVICE_STOP | SERVICE_QUERY_STATUS)};
        if ( !hService )
        {
            perror(L"OpenService()");
            dwResult = ::GetLastError();
            break;
        }

        SERVICE_STATUS_PROCESS Status = {0};
        if ( ::ControlService(hService.get(), SERVICE_CONTROL_STOP, (SERVICE_STATUS*)&Status) == 0 )
        {
            perror(L"ControlService()");
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
                perror(L"QueryServiceStatusEx()");
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
                perror(L"StopService()");
                dwResult = ERROR_TIMEOUT;
                break;
            }

            ::Sleep(Status.dwWaitHint);
        }
    } while ( false );

    ::SetLastError(dwResult);
    return Ok(dwResult);
}


auto
destroy(std::wstring_view const& ServiceName) -> Result<DWORD>
{
    DWORD dwResult = ERROR_SUCCESS;

    do
    {
        auto hManager = ServiceHandle {::OpenSCManager(nullptr, nullptr, SC_MANAGER_ALL_ACCESS)};
        if ( !hManager )
        {
            perror(L"StartService()");
            dwResult = ::GetLastError();
            break;
        }

        auto hService = ServiceHandle {::OpenService(hManager.get(), ServiceName.data(), DELETE)};
        if ( !hService )
        {
            perror(L"OpenService()");
            dwResult = ::GetLastError();
            break;
        }

        if ( ::DeleteService(hService.get()) == 0 )
        {
            perror(L"DeleteService()");
            dwResult = ::GetLastError();
            break;
        }
    } while ( false );

    ::SetLastError(dwResult);
    return Ok(dwResult);
}


auto
list() -> Result<std::vector<ServiceInfo>>
{
    std::vector<ServiceInfo> services;
    DWORD dwResult = ERROR_SUCCESS;

    do
    {
        auto hManager = ServiceHandle(::OpenSCManager(nullptr, nullptr, SC_MANAGER_ENUMERATE_SERVICE));
        if ( !hManager )
        {
            perror(L"StartService()");
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
            perror(L"EnumServicesStatusEx(1)");
            dwResult = ::GetLastError();
            break;
        }

        ok(L"BufSz={},EntryCnt={},ResumeHandle={},sizeof={}",
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
            perror(L"EnumServicesStatusEx(2)");
            dwResult = ::GetLastError();
            break;
        }

        ok(L"BufSz={}, EntryCnt={}, ResumeHandle={}, sizeof={}",
           dwBufferSize,
           dwServiceEntryCount,
           dwResumeHandle,
           sizeof(ENUM_SERVICE_STATUS_PROCESS));

        for ( u32 i = 0; i < dwServiceEntryCount; i++ )
        {
            auto service        = ServiceInfo {};
            service.Name        = Buffer[i].lpServiceName;
            service.DisplayName = Buffer[i].lpDisplayName;
            service.Status      = Buffer[i].ServiceStatusProcess.dwCurrentState;
            service.Type        = Buffer[i].ServiceStatusProcess.dwServiceType;
            service.ProcessId   = Buffer[i].ServiceStatusProcess.dwProcessId;
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


auto
is_running(const std::wstring_view& ServiceName) -> Result<bool>
{
    DWORD dwResult = ERROR_SUCCESS;
    bool bRes      = false;

    do
    {
        auto hManager = ServiceHandle(::OpenSCManager(nullptr, nullptr, SC_MANAGER_ALL_ACCESS));
        if ( !hManager )
        {
            perror(L"OpenSCManager()");
            dwResult = ::GetLastError();
            break;
        }

        auto hService = ServiceHandle(::OpenService(hManager.get(), ServiceName.data(), SERVICE_QUERY_STATUS));
        if ( !hService )
        {
            perror(L"OpenService()");
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
            perror(L"QueryServiceStatusEx()");
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

} // namespace pwn::windows::service
