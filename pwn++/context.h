#pragma once

#include "common.h"


namespace pwn::context
{
	enum class arch_t 
	{
		x86,
		x64,
		arm,
		arm_thumb,
		arm64,
		mips
	};

	extern PWNAPI arch_t arch;
}