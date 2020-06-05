#include "context.h"
#include "log.h"


namespace pwn::context
{
	namespace
	{
		DWORD __update_ptrsize()
		{
			switch ( arch )
			{
			case arch_t::x64: ptrsize = 8; break;
			case arch_t::arm64: ptrsize = 8; break;
			default: ptrsize = 4; break;
			}

			return ptrsize;
		}
	}


	PWNAPI arch_t arch = arch_t::x64;
	
	BOOL set_arch(_In_ arch_t new_arch)
	{
		switch (new_arch)
		{
			// for now we just support x64 & x86
			case arch_t::x64:
			case arch_t::x86:
				break;

			default:
				return FALSE;
		}

		arch = new_arch;
		__update_ptrsize();
		dbg(L"new architecture set to %d (ptrsz=%d)\n", new_arch, ptrsize);
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


	PWNAPI DWORD ptrsize = __update_ptrsize();
}