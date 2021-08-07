#include "registry.hpp"

// missing HKEY_CLASSES_ROOT HKEY_CURRENT_CONFIG


HKEY pwn::reg::hklm()
{
	return HKEY_LOCAL_MACHINE;
}


HKEY pwn::reg::hkcu()
{
	return HKEY_CURRENT_USER;
}


HKEY pwn::reg::hku()
{
	return HKEY_USERS;
}


_Success_(return == ERROR_SUCCESS)
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


_Success_(return == ERROR_SUCCESS)
DWORD pwn::reg::read_bool(
	_In_ HKEY hKeyRoot,
	_In_ const std::wstring& SubKey,
	_In_ const std::wstring& KeyName,
	_Out_ PBOOL lpbKeyValue
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


_Success_(return == ERROR_SUCCESS)
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

	DWORD dwBufferSize = MAX_REGSZ_VALUE_SIZE;
	auto lpwsBuffer = std::vector<WCHAR>(dwBufferSize);

	lStatus = ::RegQueryValueExW(hKey,
		KeyName.c_str(),
		0,
		NULL,
		(PBYTE)lpwsBuffer.data(),
		&dwBufferSize
	);

	if (lStatus == ERROR_SUCCESS)
		KeyValue = lpwsBuffer.data();

	::RegCloseKey(hKey);
	return lStatus;
}


_Success_(return == ERROR_SUCCESS)
DWORD pwn::reg::read_binary(
	_In_ HKEY hKeyRoot,
	_In_ const std::wstring & SubKey,
	_In_ const std::wstring & KeyName,
	_Out_ std::vector<BYTE>& KeyValue
)
{
	HKEY hKey;
	LSTATUS lStatus = ::RegOpenKeyExW(hKeyRoot, SubKey.c_str(), 0, KEY_READ, &hKey);
	if (lStatus != ERROR_SUCCESS)
		return lStatus;

	DWORD dwBufferSize = MAX_REGSZ_VALUE_SIZE;
	KeyValue.resize(dwBufferSize);

	lStatus = ::RegQueryValueExW(hKey,
		KeyName.c_str(),
		0,
		NULL,
		(PBYTE)KeyValue.data(),
		&dwBufferSize
	);

	if (lStatus == ERROR_SUCCESS)
		KeyValue.resize(dwBufferSize);

	::RegCloseKey(hKey);
	return lStatus;
}