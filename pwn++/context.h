#pragma once

#include "common.h"
#include "log.h"

namespace pwn::context
{
	enum class architecture_t
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


	extern PWNAPI architecture_t arch;
	extern PWNAPI endianess_t endian;
	extern PWNAPI u8 ptrsize;
	extern PWNAPI pwn::log::log_level_t __log_level;
	
	PWNAPI BOOL set_architecture(_In_ architecture_t new_arch);
	PWNAPI BOOL set_log_level(_In_ pwn::log::log_level_t new_level);
	PWNAPI const std::tuple<pwn::log::log_level_t, const wchar_t*> get_log_level();

}