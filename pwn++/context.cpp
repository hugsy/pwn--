#include "context.h"
#include "log.h"


namespace pwn::context
{
	PWNAPI arch_t arch = arch_t::x64;
	PWNAPI pwn::log::log_level_t log_level = pwn::log::log_level_t::LOG_INFO;
}