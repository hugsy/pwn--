#pragma once

#include "common.hpp"
#include <optional>


namespace pwn::win::cpu
{
	PWNAPI auto nb_cores() -> std::optional<u32>;
}


