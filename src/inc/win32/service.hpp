#pragma once

#include "common.hpp"
#include "handle.hpp"


namespace pwn::windows::service
{
using ServiceHandle = pwn::GenericHandle<SC_HANDLE__, CloseServiceHandle>;

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
/// @param[in] ServiceName name of the service to start
/// @param[in] ServiceBinaryPath path of the binary associated to the service
/// @return a Result object, with the last error code
///
PWNAPI auto
Create(std::wstring_view const& ServiceName, std::wstring_view const& ServiceBinaryPath) -> Result<DWORD>;


///
/// @brief
///
/// @param[in] ServiceName
/// @return DWORD
///
PWNAPI auto
Start(std::wstring_view const& ServiceName) -> Result<DWORD>;


///
/// @brief Starts a service
///
/// @param[in] ServiceName
/// @param[inopt] Timeout
/// @return DWORD
///
PWNAPI auto
Stop(std::string_view const& ServiceName, const u32 Timeout = 10000) -> Result<DWORD>;


///
/// @brief Delete a service from the service manager.
///
/// @param[in] ServiceName name of the service to delete
/// @return a Result<DWORD> of the error code of the function, sets last error on failure.
///
PWNAPI auto
Destroy(std::wstring_view const& ServiceName) -> Result<DWORD>;


///
/// @brief List all the services.
///
/// @return std::vector<ServiceInfo> An iterable of pwn::service::ServiceInfo containing basic service
/// information.
///
PWNAPI auto
List() -> Result<std::vector<ServiceInfo>>;


///
/// @brief Checks if a service is running.
///
/// @param ServiceName name of the service to query
/// @return Result<BOOL>: TRUE if the service has a running status. Throws an exception if any error occurs.
///
PWNAPI auto
IsRunning(std::wstring_view const& ServiceName) -> Result<bool>;

} // namespace pwn::windows::service
