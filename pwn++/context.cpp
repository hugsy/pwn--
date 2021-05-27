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

	PWNAPI DWORD ptrsize = __update_ptrsize();


	PWNAPI arch_t arch = arch_t::x64;
	PWNAPI endianess_t endian = endianess_t::little;
	
	BOOL set_arch(_In_ arch_t new_arch)
	{
		switch (new_arch)
		{
			// currently supported architectures
			case arch_t::x64:
			case arch_t::x86:
			case arch_t::arm64:
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


	/// <summary>
	/// Default log level defined here to Info
	/// </summary>
	PWNAPI pwn::log::log_level_t __log_level = pwn::log::log_level_t::LOG_INFO;
	
	BOOL set_log_level(_In_ pwn::log::log_level_t new_level)
	{
		__log_level = new_level;
		dbg(L"log_level set to %d\n", new_level);
		return TRUE;
	}


	const wchar_t* log_level()
	{
		return L"";
	}

}