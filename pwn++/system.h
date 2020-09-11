#pragma once

#include "common.h"

#include <string>

namespace pwn::system
{
	PWNAPI DWORD pagesize();
	PWNAPI DWORD pid(_In_ HANDLE hProcess);
	PWNAPI DWORD ppid(_In_ DWORD dwProcessId);
	PWNAPI DWORD pidof(_In_ const std::wstring& name);
	PWNAPI const std::wstring computername();
	PWNAPI const std::wstring username();
	PWNAPI const std::wstring modulename(_In_opt_ HMODULE hModule);
	PWNAPI const std::wstring filename();
}