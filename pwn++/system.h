#pragma once

#include "common.h"

#include <string>

namespace pwn::system
{
	DWORD PWNAPI pagesize();
	DWORD PWNAPI pid();
	DWORD PWNAPI ppid(_In_ DWORD dwProcessId);
	DWORD PWNAPI ppid(); 
	DWORD PWNAPI pidof(_In_ const wchar_t* lpwProcessName);
	DWORD PWNAPI pidof(_In_ const std::wstring& name);
	BOOL PWNAPI is_elevated();
}