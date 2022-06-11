#pragma once

#include "common.hpp"
#include "handle.hpp"


namespace pwn::windows::service
{
class ServiceHandle : public pwn::utils::GenericHandle<SC_HANDLE>
{
public:
    using GenericHandle<SC_HANDLE>::GenericHandle;

    auto
    close() -> bool override
    {
        if ( bool(m_handle) )
        {
            ::CloseServiceHandle(m_handle);
            m_handle = nullptr;
        }
        return true;
    }
};

using ServiceInfo = struct
{
    std::wstring Name;
    std::wstring DisplayName;
    DWORD Status;
    DWORD Type;
    DWORD ProcessId;
};


///
/// @brief Register a new service against the Windows Service Manager
///
/// @param[in] lpwszName name of the service to start
/// @param[in] lpwszPath path of the binary associated to the service
/// @return a Result object, with the last error code
///
PWNAPI auto
create(std::wstring_view const& ServiceName, std::wstring_view const& ServiceBinaryPath) -> Result<DWORD>;


///
/// @brief
///
/// @param[in] ServiceName
/// @return DWORD
///
PWNAPI auto
start(std::wstring_view const& ServiceName) -> Result<DWORD>;


///
/// @brief Starts a service
///
/// @param[in] ServiceName
/// @param[inopt] Timeout
/// @return DWORD
///
PWNAPI auto
stop(std::wstring const& ServiceName, const DWORD Timeout = 10000) -> Result<DWORD>;


///
/// @brief Delete a service from the service manager.
///
/// @param[in] ServiceName name of the service to delete
/// @return a Result<DWORD> of the error code of the function, sets last error on failure.
///
PWNAPI auto
destroy(std::wstring const& ServiceName) -> Result<DWORD>;


///
/// @brief List all the services.
///
/// @return std::vector<ServiceInfo> An iterable of pwn::service::ServiceInfo containing basic service
/// information.
///
PWNAPI auto
list() -> Result<std::vector<ServiceInfo>>;


///
/// @brief Checks if a service is running.
///
/// @param ServiceName name of the service to query
/// @return Result<BOOL>: TRUE if the service has a running status. Throws an exception if any error occurs.
///
PWNAPI auto
is_running(std::wstring_view const& ServiceName) -> Result<bool>;

} // namespace pwn::windows::service
