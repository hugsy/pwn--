#pragma once

#include <filesystem>

#include "common.hpp"
#include "handle.hpp"

namespace pwn::windows
{
///
///@brief Managed handle for service, autocall to `CloseServiceHandle` on destruction
///
///@note SC_HANDLE = struct SC_HANDLE__
///
using ServiceHandle = pwn::GenericHandle<SC_HANDLE__, CloseServiceHandle>;

///
///@brief Basic service information
///
using ServiceInfo = struct
{
    std::wstring Name;
    std::wstring DisplayName;
    std::optional<std::filesystem::path> Path;
    DWORD Status;
    DWORD Type;
    DWORD ProcessId;
};


///
///@brief Describe the service type
///
enum class ServiceType : u32
{
    OwnProcess       = SERVICE_WIN32_OWN_PROCESS,
    ShareProcess     = SERVICE_WIN32_SHARE_PROCESS,
    KernelDriver     = SERVICE_KERNEL_DRIVER,
    FileSystemDriver = SERVICE_FILE_SYSTEM_DRIVER,
};

class Service
{
public:
    ///
    /// @brief Register a new service against the Windows Service Manager
    ///
    /// @param[in] ServiceName name of the service to start
    /// @param[in] ServiceBinaryPath path of the binary associated to the service
    /// @return a Result object, with the last error code
    ///
    static Result<DWORD>
    Create(std::wstring_view const& ServiceName, std::wstring_view const& ServiceBinaryPath, ServiceType SvcType);


    ///
    /// @brief Start a service against the Windows Service Manager
    ///
    /// @param[in] ServiceName
    /// @return a Result object, with the last error code
    ///
    static Result<DWORD>
    Start(std::wstring_view const& ServiceName);


    ///
    /// @brief Stop a service
    ///
    /// @param[in] ServiceName
    /// @param[in] Timeout
    /// @return a Result object, with the last error code
    ///
    static Result<DWORD>
    Stop(std::wstring_view const& ServiceName, const u32 Timeout = 10000);


    ///
    /// @brief Delete a service from the service manager.
    ///
    /// @param[in] ServiceName name of the service to delete
    /// @return a Result<DWORD> of the error code of the function, sets last error on failure.
    ///
    static Result<DWORD>
    Destroy(std::wstring_view const& ServiceName);


    ///
    /// @brief List all the services.
    ///
    /// @return std::vector<ServiceInfo> An iterable of pwn::service::ServiceInfo containing basic service
    /// information.
    ///
    static Result<std::vector<ServiceInfo>>
    List();


    ///
    /// @brief Checks if a service is running.
    ///
    /// @param ServiceName name of the service to query
    /// @return Result<BOOL>: TRUE if the service has a running status. Throws an exception if any error occurs.
    ///
    static Result<bool>
    IsRunning(std::wstring_view const& ServiceName);
};

} // namespace pwn::windows
