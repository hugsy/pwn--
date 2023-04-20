#pragma once

#include "common.hpp"

#include <string>
#include <optional>


namespace pwn::linux::system
{
	PWNAPI auto pagesize() -> u32;
}