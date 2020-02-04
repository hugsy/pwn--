#pragma once

#include "common.h"


#define MAX_REGSZ_SIZE 255


namespace pwn::reg
{
	DWORD PWNAPI read_dword(
		_In_ HKEY hKeyRoot,
		_In_ const std::wstring& SubKey,
		_In_ const std::wstring& KeyName,
		_Out_ PDWORD lpdwKeyValue
	);

	BOOL PWNAPI read_bool(
		_In_ HKEY hKeyRoot,
		_In_ const std::wstring& SubKey,
		_In_ const std::wstring& KeyName,
		_In_ PBOOL lpbKeyValue
	);

	_Success_(return != ERROR_SUCCESS)
	DWORD PWNAPI read_wstring(
		_In_ HKEY hKeyRoot,
		_In_ const std::wstring& SubKey,
		_In_ const std::wstring& KeyName,
		_Out_ std::wstring& KeyValue
	);
}