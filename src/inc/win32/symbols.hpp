#pragma once

// clang-format off
#include "common.hpp"
// clang-format on


namespace pwn::windows
{

struct SymbolInfo
{
    u32 Type;
    u32 Size;
    u64 ModBase;
    u32 Flags;
    uptr Value;
    uptr Address;
    u32 Register;
    std::wstring Name;
};

class Symbols
{
public:
    ///
    ///@brief
    ///
    ///@return Result<std::vector<std::tuple<uptr, std::wstring>>>
    ///
    static Result<std::vector<std::tuple<uptr, std::wstring>>>
    EnumerateModules();

    ///
    ///@brief
    ///
    ///@param ModuleName
    ///@param Mask
    ///@return `Result<std::vector<SymbolInfo>>`
    ///
    static Result<std::vector<SymbolInfo>>
    EnumerateFromModule(std::wstring_view const& ModuleName, std::wstring_view const& Mask = L"*");

    ///
    ///@brief
    ///
    ///@param TargetAddress
    ///@param SymbolName
    ///@return `Result<std::wstring>`
    ///
    static Result<std::wstring>
    ResolveFromName(const uptr TargetAddress, std::wstring_view const& SymbolName);

    ///
    ///@brief
    ///
    ///@param TargetAddress
    ///@return `Result<std::wstring>`
    ///
    static Result<std::wstring>
    ResolveFromAddress(const uptr TargetAddress);

    ///
    ///@brief Set the Symbol Path object
    ///
    ///@param NewSymbolPath a wide string view with the new symbol path (e.g.
    /// L"srv*c:\symbols*https://msdl.microsoft.com/download/symbols")
    ///@return `Result<bool>` true if a custom path was set, false if using the default; or Error object on error
    ///
    static Result<bool>
    SetSymbolPath(std::wstring_view const& NewSymbolPath);
};


} // namespace pwn::windows
