#pragma once

#include "Common.hpp"


namespace pwn::Shellcode::Kernel
{

///
///@brief
///
///@return std::vector<u8>
///
std::vector<u8>
StealSystemToken();


///
///@brief
///
///@return std::vector<u8>
///
std::vector<u8>
DebugBreak();

} // namespace pwn::Shellcode::Kernel
