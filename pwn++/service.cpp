#include "service.h"

#include "log.h"
#include <stdexcept>

using namespace pwn::log;



/*++

Description:

Create a new service, with default arguments.


Arguments:

	- lpwszName is the name of the service to start
	- lpwszPath is the path of the binary associated to the service

Returns:

	The error code of the function, sets last error on failure.

--*/
auto pwn::service::create(_In_ const wchar_t* lpwszName, _In_ const wchar_t* lpwszPath) -> DWORD
{
	DWORD dwResult = ERROR_SUCCESS;

	do
	{
		auto hManager = ServiceHandle(::OpenSCManager(nullptr, nullptr, SC_MANAGER_ALL_ACCESS));
		if ( !hManager )
		{
			perror(L"OpenSCManager()");
			dwResult = ::GetLastError();
			break;
		}

		auto hService = ServiceHandle(::CreateService(
			hManager.get(), 
			lpwszName, 
			nullptr,
			SERVICE_ALL_ACCESS, 
			SERVICE_WIN32_OWN_PROCESS, 
			SERVICE_DEMAND_START, 
			SERVICE_ERROR_IGNORE, 
			lpwszPath, 
			nullptr, 
			nullptr, 
			nullptr, 
			nullptr, 
			nullptr
		));
		if ( !hService )
		{
			perror(L"CreateService()");
			dwResult = ::GetLastError();
			break;	
		}
	}
	while ( 0 );

	::SetLastError(dwResult);
	return dwResult;
}


auto pwn::service::create(_In_ const std::wstring& ServiceName, _In_ const std::wstring& ServiceBinaryPath) -> DWORD
{
	return pwn::service::create(ServiceName.c_str(), ServiceBinaryPath.c_str());
}


/*++

Description:

Start a service by name.


Arguments:
	
	- lpwszName the name of the service to start


Returns:

	The error code of the function, sets last error on failure.

--*/
auto pwn::service::start(_In_ const wchar_t* lpwszName) -> DWORD
{
	DWORD dwResult = ERROR_SUCCESS;

	do
	{
		auto hManager = ServiceHandle(::OpenSCManager(nullptr, nullptr, SC_MANAGER_ALL_ACCESS));
		if ( !hManager )
		{
			perror(L"OpenSCManager()");
			dwResult = ::GetLastError();
			break;
		}


		auto hService = ServiceHandle(::OpenService(hManager.get(), lpwszName, SERVICE_START));
		if ( !hService )
		{
			perror(L"OpenService()");
			dwResult = ::GetLastError();
			break;
		}


		if ( ::StartService(hService.get(), 0, nullptr) == 0 )
		{
			perror(L"StartService()");
			dwResult = ::GetLastError();
			break;
		}

	}
	while ( 0 );

	::SetLastError(dwResult);
	return dwResult;
}


auto pwn::service::start(_In_ const std::wstring& ServiceName) -> DWORD
{
	return  pwn::service::start(ServiceName.c_str());
}



/*++

Description:

Stops a running service by its name.


Arguments:

	- lpwszName the name of the service to stpo


Returns:

	The error code of the function, sets last error on failure.

--*/
auto pwn::service::stop(_In_ const wchar_t* lpwszName, _In_ DWORD dwTimeout) -> DWORD
{
	DWORD dwResult = ERROR_SUCCESS;
	DWORD dwBytes = 0;

	do
	{
		auto hManager = ServiceHandle(::OpenSCManager(nullptr, nullptr, SC_MANAGER_ALL_ACCESS));
		if ( !hManager )
		{
			perror(L"OpenSCManager()");
			dwResult = ::GetLastError();
			break;
		}

		auto hService = ServiceHandle(::OpenService(hManager.get(), lpwszName, SERVICE_STOP | SERVICE_QUERY_STATUS));
		if ( !hService )
		{
			perror(L"OpenService()");
			dwResult = ::GetLastError();
			break;
		}

		SERVICE_STATUS_PROCESS Status = { 0 };
		if ( ::ControlService(hService.get(), SERVICE_CONTROL_STOP, (SERVICE_STATUS*)&Status) == 0 )
		{
			perror(L"ControlService()");
			dwResult = ::GetLastError();
			break;
		}

		QWORD qwStartTime = ::GetTickCount64();


		//
		// Check that the service got correctly stopped
		//
		while ( TRUE )
		{
			if ( ::QueryServiceStatusEx(
				hService.get(), 
				SC_STATUS_PROCESS_INFO, 
				(LPBYTE)&Status,
				sizeof(SERVICE_STATUS_PROCESS), 
				&dwBytes) == 0 
			)
			{
				perror(L"QueryServiceStatusEx()");
				break;
			}

			if ( Status.dwCurrentState == SERVICE_STOPPED )
			{
				dwResult = ERROR_SUCCESS;
				break;
			}

			if ( (::GetTickCount64() - qwStartTime) > dwTimeout )
			{
				err(L"pwn::service::stop('%s') got WAIT_TIMEOUT\n", lpwszName);
				dwResult = ERROR_TIMEOUT;
				break;
			}

			::Sleep(Status.dwWaitHint);
		}
	}
	while ( 0 );

	::SetLastError(dwResult);
	return dwResult;
}


auto pwn::service::stop(_In_ const std::wstring& ServiceName, _In_ DWORD dwTimeout) -> DWORD
{
	return  pwn::service::stop(ServiceName.c_str(), dwTimeout);
}


/*++

Description:

Delete a service from the service manager.


Arguments:

	- lpwszName the name of the service to delete


Returns:

	The error code of the function, sets last error on failure.

--*/
auto pwn::service::destroy(_In_ const wchar_t* lpwszName) -> DWORD
{
	DWORD dwResult = ERROR_SUCCESS;

	do
	{
		auto hManager = ServiceHandle(::OpenSCManager(nullptr, nullptr, SC_MANAGER_ALL_ACCESS));
		if ( !hManager )
		{
			perror(L"StartService()");
			dwResult = ::GetLastError();
			break;
		}

		auto hService = ServiceHandle(::OpenService(hManager.get(), lpwszName, DELETE));
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
	}
	while ( 0 );

	::SetLastError(dwResult);
	return dwResult;
}


auto pwn::service::destroy(_In_ const std::wstring& ServiceName) -> DWORD
{
	return pwn::service::destroy(ServiceName.c_str());
}


/*++

Description:

List all the services.


Arguments:

	None


Returns:

	An iterable of pwn::service::service_info_t containing basic service information.

--*/
auto pwn::service::list() -> std::vector<pwn::service::service_info_t>
{
	std::vector<pwn::service::service_info_t> services;
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

		DWORD dwBufferSize = 0;
		DWORD dwServiceEntryCount = 0;
		DWORD dwResumeHandle = 0;
		
		BOOL bRes = ::EnumServicesStatusEx(
			hManager.get(),
			SC_ENUM_PROCESS_INFO,
			SERVICE_KERNEL_DRIVER | SERVICE_FILE_SYSTEM_DRIVER | SERVICE_WIN32_OWN_PROCESS | SERVICE_WIN32_SHARE_PROCESS,
			SERVICE_STATE_ALL,
			nullptr,
			0,
			&dwBufferSize,
			&dwServiceEntryCount,
			&dwResumeHandle,
			nullptr
		);
		if ((bRes == 0) && ::GetLastError() != ERROR_MORE_DATA)
		{
			perror(L"EnumServicesStatusEx(1)");
			dwResult = ::GetLastError();
			break;
		}

		ok(L"BufSz=%lu,EntryCnt=%lu,ResumeHandle=%lu,sizeof=%lu\n", dwBufferSize, dwServiceEntryCount, dwResumeHandle, sizeof(ENUM_SERVICE_STATUS_PROCESS));
		auto Buffer = std::make_unique<ENUM_SERVICE_STATUS_PROCESS[]>(dwBufferSize);

		if ( ::EnumServicesStatusEx(
			hManager.get(),
			SC_ENUM_PROCESS_INFO,
			SERVICE_KERNEL_DRIVER | SERVICE_FILE_SYSTEM_DRIVER | SERVICE_WIN32_OWN_PROCESS | SERVICE_WIN32_SHARE_PROCESS,
			SERVICE_STATE_ALL,
			reinterpret_cast<LPBYTE>(Buffer.get()),
			dwBufferSize,
			&dwBufferSize,
			&dwServiceEntryCount,
			&dwResumeHandle,
			nullptr
		) == 0 )
		{
			perror(L"EnumServicesStatusEx(2)");
			dwResult = ::GetLastError();
			break;
		}

		ok(L"BufSz=%lu,EntryCnt=%lu,ResumeHandle=%lu,sizeof=%lu\n", dwBufferSize, dwServiceEntryCount, dwResumeHandle, sizeof(ENUM_SERVICE_STATUS_PROCESS));

		for (DWORD i = 0; i < dwServiceEntryCount; i++ )
		{
			auto service = service_info_t{};
			service.Name = Buffer[i].lpServiceName;
			service.DisplayName = Buffer[i].lpDisplayName;
			service.Status = Buffer[i].ServiceStatusProcess.dwCurrentState;
			service.Type = Buffer[i].ServiceStatusProcess.dwServiceType;
			service.ProcessId = Buffer[i].ServiceStatusProcess.dwProcessId;
			services.push_back(service);
		}
		
	}
	while ( 0 );

	if ( dwResult != ERROR_SUCCESS )
	{
		::SetLastError(dwResult);
		throw std::runtime_error("an error occured in pwn::service::list()");
	}

	return services;
}


/*++

Description:

Checks if a service is running.


Arguments:

	- lpwszName the name of the service to query


Returns:

	A boolean set to TRUE if the service has a running status. Throws an exception if any error occurs.

--*/
auto pwn::service::is_running(_In_ const wchar_t* lpwszName) -> BOOL
{
	DWORD dwResult = ERROR_SUCCESS;
	BOOL bRes = FALSE;

	do
	{
		auto hManager = ServiceHandle(::OpenSCManager(nullptr, nullptr, SC_MANAGER_ALL_ACCESS));
		if ( !hManager )
		{
			perror(L"OpenSCManager()");
			dwResult = ::GetLastError();
			break;
		}

		auto hService = ServiceHandle(::OpenService(hManager.get(), lpwszName, SERVICE_QUERY_STATUS));
		if ( !hService )
		{
			perror(L"OpenService()");
			dwResult = ::GetLastError();
			break;
		}

		DWORD dwBytes = 0;
		SERVICE_STATUS_PROCESS Status = { 0 };
		if ( ::QueryServiceStatusEx(
			hService.get(),
			SC_STATUS_PROCESS_INFO,
			(LPBYTE)&Status,
			sizeof(SERVICE_STATUS_PROCESS),
			&dwBytes) == 0
		)
		{
			perror(L"QueryServiceStatusEx()");
			break;
		}

		dwResult = ERROR_SUCCESS;

		if ( Status.dwCurrentState == SERVICE_RUNNING )
		{
			bRes = TRUE;
		}
	}
	while ( 0 );

	if ( dwResult != ERROR_SUCCESS )
	{
		::SetLastError(dwResult);
		throw std::runtime_error("an error occured in pwn::service::is_running()");
	}

	return bRes;
}


auto pwn::service::is_running(_In_ const std::wstring& ServiceName) -> BOOL
{
	return pwn::service::is_running(ServiceName.c_str());
}
