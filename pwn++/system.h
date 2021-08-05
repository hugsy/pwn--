#pragma once

#include "common.h"

#include <string>

namespace pwn::system
{
	PWNAPI auto pagesize() -> DWORD;
	PWNAPI auto pid(_In_ HANDLE hProcess) -> DWORD;
	PWNAPI auto ppid(_In_ DWORD dwProcessId) -> DWORD;
	PWNAPI auto pidof(_In_ const std::wstring& name) -> DWORD;
	PWNAPI auto computername() -> const std::wstring;
	PWNAPI auto username() -> const std::wstring;
	PWNAPI auto modulename(_In_opt_ HMODULE hModule) -> const std::wstring;
	PWNAPI auto filename() -> const std::wstring;
}