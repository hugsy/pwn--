#pragma once

#include "common.h"



/**
 * Shellcode source: https://gist.github.com/hugsy/763ec9e579796c35411a5929ae2aca27
 */


namespace pwn::kernel
{
	namespace shellcode
	{
		PWNAPI std::vector<BYTE> steal_system_token(void);
		PWNAPI std::vector<BYTE> debug_break(void);
	}
}

