#pragma once

#include "common.h"

// https://docs.microsoft.com/en-us/windows/win32/sysinfo/registry-element-size-limits

#define MAX_REGSZ_KEY_SIZE 255
#define MAX_REGSZ_VALUE_NAME_SIZE 16383 
#define MAX_REGSZ_VALUE_SIZE 1*1024*1024 // arbirary value, todo: fix



namespace pwn::reg
{
	HKEY PWNAPI hklm();
	HKEY PWNAPI hkcu();
	HKEY PWNAPI hku();


	_Success_(return == ERROR_SUCCESS) DWORD PWNAPI read_bool(
		_In_ HKEY hKeyRoot,
		_In_ const std::wstring& SubKey,
		_In_ const std::wstring& KeyName,
		_Out_ PBOOL lpbKeyValue
	);

	_Success_(return == ERROR_SUCCESS) DWORD PWNAPI read_dword(
		_In_ HKEY hKeyRoot,
		_In_ const std::wstring& SubKey,
		_In_ const std::wstring& KeyName,
		_Out_ PDWORD lpdwKeyValue
	);

	_Success_(return == ERROR_SUCCESS) DWORD PWNAPI read_wstring(
		_In_ HKEY hKeyRoot,
		_In_ const std::wstring& SubKey,
		_In_ const std::wstring& KeyName,
		_Out_ std::wstring& KeyValue
	);

	_Success_(return == ERROR_SUCCESS) DWORD PWNAPI read_binary(
			_In_ HKEY hKeyRoot,
			_In_ const std::wstring & SubKey,
			_In_ const std::wstring & KeyName,
			_Out_ std::vector<BYTE> & KeyValue
	);

}