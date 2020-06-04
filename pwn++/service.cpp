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
DWORD pwn::service::create(_In_ const wchar_t* lpwszName, _In_ const wchar_t* lpwszPath)
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
			hManager.Get(), 
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


DWORD pwn::service::create(_In_ const std::wstring& ServiceName, _In_ const std::wstring& ServiceBinaryPath)
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
DWORD pwn::service::start(_In_ const wchar_t* lpwszName)
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


		auto hService = ServiceHandle(::OpenService(hManager.Get(), lpwszName, SERVICE_START));
		if ( !hService )
		{
			perror(L"OpenService()");
			dwResult = ::GetLastError();
			break;
		}


		if ( !StartService(hService.Get(), 0, nullptr) )
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


DWORD pwn::service::start(_In_ const std::wstring& ServiceName)
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
DWORD pwn::service::stop(_In_ const wchar_t* lpwszName, _In_ DWORD dwTimeout)
{
	DWORD dwResult = ERROR_SUCCESS, dwBytes = 0;

	do
	{
		auto hManager = ServiceHandle(::OpenSCManager(nullptr, nullptr, SC_MANAGER_ALL_ACCESS));
		if ( !hManager )
		{
			perror(L"OpenSCManager()");
			dwResult = ::GetLastError();
			break;
		}

		auto hService = ServiceHandle(::OpenService(hManager.Get(), lpwszName, SERVICE_STOP | SERVICE_QUERY_STATUS));
		if ( !hService )
		{
			perror(L"OpenService()");
			dwResult = ::GetLastError();
			break;
		}

		SERVICE_STATUS_PROCESS Status = { 0 };
		if ( !::ControlService(hService.Get(), SERVICE_CONTROL_STOP, (SERVICE_STATUS*)&Status) )
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
			if ( !::QueryServiceStatusEx(
				hService.Get(), 
				SC_STATUS_PROCESS_INFO, 
				(LPBYTE)&Status,
				sizeof(SERVICE_STATUS_PROCESS), 
				&dwBytes) 
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


DWORD pwn::service::stop(_In_ const std::wstring& ServiceName, _In_ DWORD dwTimeout)
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
DWORD pwn::service::destroy(_In_ const wchar_t* lpwszName)
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

		auto hService = ServiceHandle(::OpenService(hManager.Get(), lpwszName, DELETE));
		if ( !hService )
		{
			perror(L"OpenService()");
			dwResult = ::GetLastError();
			break;
		}

		if ( !::DeleteService(hService.Get()) )
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


DWORD pwn::service::destroy(_In_ const std::wstring& ServiceName)
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
std::vector<pwn::service::service_info_t> pwn::service::list()
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

		DWORD dwBufferSize = 0, dwServiceEntryCount = 0, dwResumeHandle = 0;
		
		BOOL bRes = ::EnumServicesStatusEx(
			hManager.Get(),
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
		if (!bRes && ::GetLastError() != ERROR_MORE_DATA)
		{
			perror(L"EnumServicesStatusEx(1)");
			dwResult = ::GetLastError();
			break;
		}

		ok(L"BufSz=%lu,EntryCnt=%lu,ResumeHandle=%lu,sizeof=%lu\n", dwBufferSize, dwServiceEntryCount, dwResumeHandle, sizeof(ENUM_SERVICE_STATUS_PROCESS));
		auto Buffer = std::make_unique<ENUM_SERVICE_STATUS_PROCESS[]>(dwBufferSize);

		if ( !::EnumServicesStatusEx(
			hManager.Get(),
			SC_ENUM_PROCESS_INFO,
			SERVICE_KERNEL_DRIVER | SERVICE_FILE_SYSTEM_DRIVER | SERVICE_WIN32_OWN_PROCESS | SERVICE_WIN32_SHARE_PROCESS,
			SERVICE_STATE_ALL,
			reinterpret_cast<LPBYTE>(Buffer.get()),
			dwBufferSize,
			&dwBufferSize,
			&dwServiceEntryCount,
			&dwResumeHandle,
			nullptr
		) )
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
BOOL pwn::service::is_running(_In_ const wchar_t* lpwszName)
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

		auto hService = ServiceHandle(::OpenService(hManager.Get(), lpwszName, SERVICE_QUERY_STATUS));
		if ( !hService )
		{
			perror(L"OpenService()");
			dwResult = ::GetLastError();
			break;
		}

		DWORD dwBytes = 0;
		SERVICE_STATUS_PROCESS Status = { 0 };
		if ( !::QueryServiceStatusEx(
			hService.Get(),
			SC_STATUS_PROCESS_INFO,
			(LPBYTE)&Status,
			sizeof(SERVICE_STATUS_PROCESS),
			&dwBytes)
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


BOOL pwn::service::is_running(_In_ const std::wstring& ServiceName)
{
	return pwn::service::is_running(ServiceName.c_str());
}
