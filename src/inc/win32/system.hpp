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

#include <optional>
#include <string>

#include "common.hpp"


namespace pwn::windows
{
class System
{
public:
    static auto
    PageSize() -> u32;

    static u32
    ProcessId(const HANDLE hProcess);

    static std::optional<u32>
    ParentProcessId(const u32 dwProcessId);

    static auto
    PidOf(std::wstring_view const& targetProcessName) -> Result<std::vector<u32>>;

    static const std::wstring
    ComputerName();

    static Result<std::wstring>
    UserName();

    static Result<std::wstring>
    ModuleName(HMODULE hModule);

    static Result<std::wstring>
    FileName();

    ///
    /// @brief Get the Windows version as a tuple of int, or raise an exception.
    ///
    /// @return PWNAPI
    ///
    static std::tuple<u32, u32, u32>
    WindowsVersion();

    ///
    /// @brief Query system information
    ///
    /// @tparam T
    /// @param SystemInformationClass
    /// @return Result<std::shared_ptr<T>>
    ///
    template<class T>
    static Result<std::shared_ptr<T>>
    Query(SYSTEM_INFORMATION_CLASS SystemInformationClass)
    {
        auto res = QueryInternal(SystemInformationClass, sizeof(T));
        if ( Failed(res) )
        {
            return Err(Error(res).code);
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
    static Result<std::tuple<u8, u8, u8, u8, u8>>
    ProcessorCount();


    ///
    /// @brief Get the kernel modules
    ///
    /// @return Result<std::vector<RTL_PROCESS_MODULE_INFORMATION>>
    ///
    static Result<std::vector<RTL_PROCESS_MODULE_INFORMATION>>
    Modules();


    ///
    /// @brief Enumerate all the system handles
    ///
    /// @return Result<std::vector<SYSTEM_HANDLE_TABLE_ENTRY_INFO>>
    ///
    static Result<std::vector<SYSTEM_HANDLE_TABLE_ENTRY_INFO>>
    Handles();

private:
    ///
    /// @brief Should not be called directly
    ///
    /// @param SystemInformationClass
    ///
    /// @return Result<PVOID>
    ///
    static Result<PVOID>
    QueryInternal(const SYSTEM_INFORMATION_CLASS, const usize);
};

} // namespace pwn::windows
