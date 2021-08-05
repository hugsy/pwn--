#pragma once

#include "common.h"
#include "handle.h"

namespace pwn::service
{
	class ServiceHandle : public pwn::utils::GenericHandle<SC_HANDLE>
	{
	public:
		using GenericHandle<SC_HANDLE>::GenericHandle;

		auto close() -> bool override
		{
			if ( bool(m_handle) )
			{
				::CloseServiceHandle(m_handle);
				m_handle = nullptr;
			}
			return true;
		}
	};

	using service_info_t = struct 
	{
		std::wstring Name;
		std::wstring DisplayName;
		DWORD Status;
		DWORD Type;
		DWORD ProcessId;
	};


	PWNAPI auto create(_In_ const wchar_t* lpwszName, _In_ const wchar_t* lpwszPath) -> DWORD;
	PWNAPI auto create(_In_ const std::wstring& ServiceName, _In_ const std::wstring& ServiceBinaryPath) -> DWORD; 

	PWNAPI auto start(_In_ const wchar_t* lpwszName) -> DWORD;
	PWNAPI auto start(_In_ const std::wstring& ServiceName) -> DWORD;

	PWNAPI auto stop(_In_ const wchar_t* lpwszName, _In_ DWORD dwTimeout = 10000) -> DWORD;
	PWNAPI auto stop(_In_ const std::wstring& ServiceName, _In_ DWORD dwTimeout = 10000) -> DWORD;

	PWNAPI auto destroy(_In_ const wchar_t* lpwszName) -> DWORD;
	PWNAPI auto destroy(_In_ const std::wstring& ServiceName) -> DWORD;

	PWNAPI auto list() -> std::vector<service_info_t>;

	PWNAPI auto is_running(_In_ const wchar_t* lpwszName) -> BOOL;
	PWNAPI auto is_running(_In_ const std::wstring& ServiceName) -> BOOL;

}