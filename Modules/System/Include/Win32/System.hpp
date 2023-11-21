///
/// @file system.hpp
/// @author hugsy (hugsy@blah.cat)
/// @brief Header for `pwn::windows::System` class
/// This namespace holds functions for global system manipulation. For process specific stuff,
/// use the `pwn::windows::Process` class.
///
/// @copyright This file is part of the `pwn++` project and subject to the same license
///

#pragma once

#include "Common.hpp"


namespace pwn::System
{

namespace details
{
///
/// @brief Should not be called directly
///
/// @param SystemInformationClass
///
/// @return Result<PVOID>
///
Result<PVOID>
QueryInternal(const SYSTEM_INFORMATION_CLASS, const usize);
} // namespace details

///
///@brief Get the page size of the targeted system
///
///@return u32
///
auto
PageSize() -> u32;

///
///@brief
///
///@param hProcess
///@return u32
///
u32
ProcessId(const HANDLE hProcess = ::GetCurrentProcess());


///
///@brief
///
///@param dwProcessId
///@return std::optional<u32>
///
auto
ParentProcessId(const u32 dwProcessId) -> Result<u32>;

///
///@brief
///
///@param targetProcessName
///@return Result<std::vector<u32>>
///
auto
PidOf(std::wstring_view const targetProcessName) -> Result<std::vector<u32>>;

///
///@brief
///
///@return const std::wstring
///
const std::wstring
ComputerName();

///
///@brief
///
///@return Result<std::wstring>
///
Result<std::wstring>
UserName();

///
///@brief
///
///@param hModule
///@return Result<std::wstring>
///
Result<std::wstring>
ModuleName(HMODULE hModule);

///
///@brief
///
///@return Result<std::wstring>
///
Result<std::wstring>
FileName();

///
/// @brief Get the Windows version as a tuple of int, or raise an exception.
///
/// @return PWNAPI
///
std::tuple<u32, u32, u32>
WindowsVersion();

///
/// @brief Query system information
///
/// @tparam T
/// @param SystemInformationClass
/// @return Result<std::shared_ptr<T>>
///
template<class T>
Result<std::shared_ptr<T>>
Query(SYSTEM_INFORMATION_CLASS SystemInformationClass)
{
    auto res = details::QueryInternal(SystemInformationClass, sizeof(T));
    if ( Failed(res) )
    {
        return Error(res);
    }

    const auto p = reinterpret_cast<T*>(Value(res));
    auto deleter = [](T* x)
    {
        ::LocalFree(x);
    };
    return Ok(std::shared_ptr<T>(p, deleter));
}


///
/// @brief Retrieves the system number of processors and their cache
///
/// @return If successful, the tuple returns a tuple of (in that order):
/// processor count, logical processor count, number of L1 caches, number
/// of L2 caches and number of L3 caches
///
Result<std::tuple<u8, u8, u8, u8, u8>>
ProcessorCount();


///
/// @brief Get the kernel modules
///
/// @return Result<std::vector<RTL_PROCESS_MODULE_INFORMATION>>
///
Result<std::vector<RTL_PROCESS_MODULE_INFORMATION>>
Modules();


///
/// @brief Enumerate all the system handles
///
/// @return Result<std::vector<SYSTEM_HANDLE_TABLE_ENTRY_INFO>>
///
Result<std::vector<SYSTEM_HANDLE_TABLE_ENTRY_INFO>>
Handles();


///
///@brief Enumerate all {ProcessId, ThreadId} currently running
///
///@return Result<std::vector<std::tuple<u32, u32>>>
///
Result<std::vector<std::tuple<u32, u32>>>
Threads();
} // namespace pwn::System
