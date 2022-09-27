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


namespace pwn::windows
{
class System
{
public:
    static auto
    PageSize() -> u32;

    static auto
    ProcessId(_In_ HANDLE hProcess) -> u32;

    static auto
    ParentProcessId(_In_ u32 dwProcessId) -> std::optional<u32>;

    static auto
    PidOf(std::wstring_view const& targetProcessName) -> Result<std::vector<u32>>;

    static auto
    ComputerName() -> const std::wstring;

    static auto
    UserName() -> const std::wstring;

    static auto
    ModuleName(_In_opt_ HMODULE hModule) -> std::optional<std::wstring>;

    static auto
    FileName() -> std::optional<std::wstring>;

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
