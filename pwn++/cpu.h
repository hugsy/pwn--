#pragma once

#include "common.h"


namespace pwn::cpu
{
	_Success_(return != -1) PWNAPI auto nb_cores() -> DWORD;
}


