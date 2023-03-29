///
/// @file object.hpp
/// @author hugsy (hugsy@blah.cat)
/// @brief
///
/// @copyright This file is part of the `pwn++` project and subject to the same license
///
#pragma once

#include "Common.hpp"

namespace pwn::System
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


    ///
    /// @brief Get a vector of big pool chunks with the specified Tag
    ///
    /// @param Tag is a u32 of the big pool tag to search for. If 0, all big pool chunks are returned.
    /// @return Result<std::vector<uptr>> A vector with the big pool kernel address with the specified tag
    ///
    /// @note This function is just a helper for System::Query(SystemBigPoolInformation)
    /// @link https://blahcat.github.io/posts/2019/03/17/small-dumps-in-the-big-pool.html
    ///
    static Result<std::vector<uptr>>
    FindBigPoolAddressesFromTag(const u32 Tag);

private:
};
} // namespace System
