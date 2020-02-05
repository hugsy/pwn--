#pragma once

#include "common.h"

#include <string>

namespace pwn::system
{
	PWNAPI DWORD pagesize();
	PWNAPI DWORD pid(_In_ HANDLE hProcess);
	PWNAPI DWORD pid();
	PWNAPI DWORD ppid(_In_ DWORD dwProcessId);
	PWNAPI DWORD ppid(); 
	PWNAPI DWORD pidof(_In_ const wchar_t* lpwProcessName);
	PWNAPI DWORD pidof(_In_ const std::wstring& name);
	PWNAPI BOOL is_elevated();
	PWNAPI const std::wstring name();
	
}