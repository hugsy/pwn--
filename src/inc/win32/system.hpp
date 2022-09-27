///
/// @file system.hpp
/// @author hugsy (hugsy@blah.cat)
/// @brief Header `for pwn::windowsdows::system`
/// This namespace holds functions for global system manipulation. For process specific stuff, see the
/// `pwn::windowsdows::process` namespace.
///


#pragma once

#include <optional>
#include <string>

#include "common.hpp"


namespace pwn::windows::system
{
PWNAPI auto
PageSize() -> u32;

PWNAPI auto
ProcessId(_In_ HANDLE hProcess) -> u32;

PWNAPI auto
ParentProcessId(_In_ u32 dwProcessId) -> std::optional<u32>;

PWNAPI auto
PidOf(std::wstring_view const& targetProcessName) -> Result<std::vector<u32>>;

PWNAPI auto
ComputerName() -> const std::wstring;

PWNAPI auto
username() -> const std::wstring;

PWNAPI auto
modulename(_In_opt_ HMODULE hModule) -> std::optional<std::wstring>;

PWNAPI auto
filename() -> std::optional<std::wstring>;

///
/// @brief Get the Windows version as a tuple of int, or raise an exception.
///
/// @return PWNAPI
///
PWNAPI
std::tuple<u32, u32, u32>
WindowsVersion();
} // namespace pwn::windows::system
