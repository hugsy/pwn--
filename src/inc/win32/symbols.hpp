#pragma once

// clang-format off
#include "common.hpp"

#include <DbgHelp.h>
// clang-format on


namespace pwn::windows
{

class Symbols
{
public:
    static Result<std::vector<std::tuple<uptr, std::wstring>>>
    EnumerateModules();

    static Result<std::vector<SYMBOL_INFO>>
    EnumerateFromModule(std::wstring_view const& ModuleName, std::wstring_view const& Mask = L"*");

    static Result<std::wstring>
    ResolveFromName(const uptr TargetAddress, std::wstring_view const& SymbolName);

    static Result<std::wstring>
    ResolveFromAddress(const uptr TargetAddress);
};


} // namespace pwn::windows
