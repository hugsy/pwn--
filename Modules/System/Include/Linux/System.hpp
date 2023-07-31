#pragma once

#include <optional>
#include <string>

#include "Common.hpp"


namespace pwn::Linux::System
{
///
///@brief Return the system page size
///
///@return u32
///
PWNAPI u32
PageSize();
} // namespace pwn::Linux::System
