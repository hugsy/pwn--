#pragma once

#include "common.h"
#include "handle.h"

namespace pwn::service
{
	class ServiceHandle : public pwn::generic::GenericHandle<SC_HANDLE>
	{
	public:
		using GenericHandle<SC_HANDLE>::GenericHandle;

		void Close() override
		{
			if ( bool(_h) )
			{
				::CloseServiceHandle(_h);
				_h = nullptr;
			}
		}
	};

	typedef struct 
	{
		std::wstring Name;
		std::wstring DisplayName;
		DWORD Status;
		DWORD Type;
		DWORD ProcessId;
	} service_info_t;


	PWNAPI DWORD create(_In_ const wchar_t* lpwszName, _In_ const wchar_t* lpwszPath);
	PWNAPI DWORD create(_In_ const std::wstring& ServiceName, _In_ const std::wstring& ServiceBinaryPath); 

	PWNAPI DWORD start(_In_ const wchar_t* lpwszName);
	PWNAPI DWORD start(_In_ const std::wstring& ServiceName);

	PWNAPI DWORD stop(_In_ const wchar_t* lpwszName, _In_ DWORD dwTimeout = 10000);
	PWNAPI DWORD stop(_In_ const std::wstring& ServiceName, _In_ DWORD dwTimeout = 10000);

	PWNAPI DWORD destroy(_In_ const wchar_t* lpwszName);
	PWNAPI DWORD destroy(_In_ const std::wstring& ServiceName);

	PWNAPI std::vector<service_info_t> list();

	PWNAPI BOOL is_running(_In_ const wchar_t* lpwszName);
	PWNAPI BOOL is_running(_In_ const std::wstring& ServiceName);

}