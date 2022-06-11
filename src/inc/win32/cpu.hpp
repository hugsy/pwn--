#pragma once

#include <optional>

#include "common.hpp"


namespace pwn::windows::cpu
{
PWNAPI auto
nb_cores() -> std::optional<u32>;
}
