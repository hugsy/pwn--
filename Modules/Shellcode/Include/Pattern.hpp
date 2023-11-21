#pragma once

#include "Common.hpp"


namespace pwn::Shellcode
{

///
///@brief
///
///@param Bytes
///@param Needle
///@param NeedleMask
///
///@return ssize
///
ssize
PatternFind(std::vector<u8> const& Bytes, std::vector<u8> const& Needle, std::vector<u8> const& NeedleMask);

///
///@brief
///
///@param Bytes
///@param Needle
///
///@return ssize
///
ssize
PatternFind(std::vector<u8> const& Bytes, std::vector<u8> const& Needle);

} // namespace pwn::Shellcode
