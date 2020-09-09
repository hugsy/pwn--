#pragma once

#include "common.h"
#include "log.h"

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

	enum class endianess_t
	{
		little,
		big,
	};


	extern PWNAPI arch_t arch;
	extern PWNAPI endianess_t endian;
	
	PWNAPI BOOL set_arch(_In_ arch_t new_arch);

	extern PWNAPI pwn::log::log_level_t log_level;
	PWNAPI BOOL set_log_level(_In_ pwn::log::log_level_t new_level);

	extern PWNAPI DWORD ptrsize;
}