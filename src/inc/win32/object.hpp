///
/// @file object.hpp
/// @author hugsy (hugsy@blah.cat)
/// @brief
///
/// @copyright This file is part of the `pwn++` project and subject to the same license
///
#pragma once

#include "common.hpp"

namespace pwn::windows
{
class ObjectManager
{
public:
    ///
    /// @brief
    ///
    /// @param Root
    /// @return Result<std::vector<std::pair<std::wstring, std::wstring>>>
    ///
    static Result<std::vector<std::pair<std::wstring, std::wstring>>>
    EnumerateDirectory(std::wstring_view const& Root);

private:
};
} // namespace pwn::windows
