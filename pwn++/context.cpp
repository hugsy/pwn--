#include "context.h"
#include "log.h"


namespace pwn::context
{
	PWNAPI arch_t arch = arch_t::x64;
	
	BOOL set_arch(_In_ arch_t new_arch)
	{
		// for now we just support x64 & x86
		if ( new_arch != arch_t::x64 && new_arch != arch_t::x86 )
			return FALSE;

		arch = new_arch;
		dbg(L"new architecture set to %d\n", new_arch);
		// TODO: add hooks that triggers on arch change
		return TRUE;
	}


	PWNAPI pwn::log::log_level_t log_level = pwn::log::log_level_t::LOG_INFO;
	
	BOOL set_log_level(_In_ pwn::log::log_level_t new_level)
	{
		log_level = new_level;
		dbg(L"log_level set to %d\n", new_level);
		return TRUE;
	}
}