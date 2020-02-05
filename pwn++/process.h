#pragma once

#include "common.h"


namespace pwn::process
{
	_Success_(return == ERROR_SUCCESS) DWORD PWNAPI get_integrity_level(_In_ DWORD dwProcessId, _Out_ std::wstring & IntegrityLevelName);
	_Success_(return == ERROR_SUCCESS) DWORD PWNAPI get_integrity_level(_Out_ std::wstring & IntegrityLevelName);
	_Success_(return) BOOL PWNAPI execve(_In_ const wchar_t* lpCommandLine, _Out_opt_ LPHANDLE lpNewProcessHandle = nullptr);

}
