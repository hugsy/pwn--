#pragma once

#include "common.h"

namespace pwn::service
{
	//
	// straight copy/paste from @zodiacon "Windows 10 System Programming"
	//
	class ServiceHandle
	{
	public:
		explicit ServiceHandle(SC_HANDLE h = nullptr) :_h(h) {}
		~ServiceHandle() { Close(); }
		ServiceHandle(const ServiceHandle&) = delete;
		ServiceHandle& operator=(const ServiceHandle&) = delete;
		ServiceHandle(ServiceHandle&& other) noexcept: _h(other._h) { other._h = nullptr; }
		ServiceHandle& operator=(ServiceHandle&& other) noexcept
		{
			if ( this != &other )
			{
				Close();
				_h = other._h;
				other._h = nullptr;
			}
			return*this;
		}

		operator bool() const
		{
			return _h != nullptr && _h != INVALID_HANDLE_VALUE;
		}

		SC_HANDLE Get() const
		{
			return _h;
		}

		void Close()
		{
			if ( bool(_h) )
			{
				::CloseServiceHandle(_h);
				_h = nullptr;
			}
		}

	private:
		SC_HANDLE _h;
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