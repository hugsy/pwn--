#pragma once

#include "common.hpp"

#include <string>
#include <optional>


namespace pwn::win::system
{
	PWNAPI auto pagesize() -> u32;
	PWNAPI auto pid(_In_ HANDLE hProcess) -> u32;
	PWNAPI auto ppid(_In_ u32 dwProcessId) -> std::optional<u32>;
	PWNAPI auto pidof(_In_ const std::wstring& name) -> std::optional<u32>;
	PWNAPI auto computername() -> const std::wstring;
	PWNAPI auto username() -> const std::wstring;
	PWNAPI auto modulename(_In_opt_ HMODULE hModule) -> std::optional<std::wstring>;
	PWNAPI auto filename() -> std::optional<std::wstring>;
}