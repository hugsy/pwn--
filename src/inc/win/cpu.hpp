#pragma once

#include "common.hpp"


namespace pwn::cpu
{
	_Success_(return != -1) PWNAPI auto nb_cores() -> DWORD;
}


