#include "registry.h"



DWORD pwn::reg::read_dword(
	_In_ HKEY hKeyRoot,
	_In_ const std::wstring& SubKey,
	_In_ const std::wstring& KeyName,
	_Out_ PDWORD lpdwKeyValue
)
{
	HKEY hKey;
	LSTATUS lStatus = ::RegOpenKeyExW(hKeyRoot, SubKey.c_str(), 0, KEY_READ, &hKey);
	if (lStatus != ERROR_SUCCESS)
		return lStatus;

	DWORD dwKeyValueSize = sizeof(DWORD);

	lStatus = ::RegQueryValueExW(hKey,
		KeyName.c_str(),
		0,
		NULL,
		(PBYTE)lpdwKeyValue,
		&dwKeyValueSize
	);

	::RegCloseKey(hKey);
	return lStatus;
}


BOOL pwn::reg::read_bool(
	_In_ HKEY hKeyRoot,
	_In_ const std::wstring& SubKey,
	_In_ const std::wstring& KeyName,
	_In_ PBOOL lpbKeyValue
)
{
	HKEY hKey;
	LSTATUS lStatus = ::RegOpenKeyExW(hKeyRoot, SubKey.c_str(), 0, KEY_READ, &hKey);
	if (lStatus != ERROR_SUCCESS)
		return lStatus;

	DWORD dwKeyValueSize = sizeof(BOOL);

	lStatus = ::RegQueryValueExW(hKey,
		KeyName.c_str(),
		0,
		NULL,
		(PBYTE)lpbKeyValue,
		&dwKeyValueSize
	);

	::RegCloseKey(hKey);
	return lStatus;
}


_Success_(return != ERROR_SUCCESS)
DWORD pwn::reg::read_wstring(
	_In_ HKEY hKeyRoot,
	_In_ const std::wstring& SubKey,
	_In_ const std::wstring& KeyName,
	_Out_ std::wstring& KeyValue
)
{
	HKEY hKey;
	LSTATUS lStatus = ::RegOpenKeyExW(hKeyRoot, SubKey.c_str(), 0, KEY_READ, &hKey);
	if (lStatus != ERROR_SUCCESS)
		return lStatus;

	WCHAR lpwsBuffer[MAX_REGSZ_SIZE] = { 0 };
	DWORD dwBufferSize = MAX_REGSZ_SIZE;

	lStatus = ::RegQueryValueExW(hKey,
		KeyName.c_str(),
		0,
		NULL,
		(PBYTE)lpwsBuffer,
		&dwBufferSize
	);

	if (lStatus == ERROR_SUCCESS)
		KeyValue = lpwsBuffer;

	RegCloseKey(hKey);
	return lStatus;
}
