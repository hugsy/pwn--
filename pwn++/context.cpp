#include "context.h"
#include "log.h"


namespace pwn::context
{
	PWNAPI architecture_t arch = architecture_t::x64;
	PWNAPI endianess_t endian = endianess_t::little;
	PWNAPI u8 ptrsize = 8;
	
	BOOL set_architecture(_In_ architecture_t new_arch)
	{
		switch (new_arch)
		{
			// currently supported architectures
			case architecture_t::x64:
				arch = architecture_t::x64;
				endian = endianess_t::little;
				ptrsize = 8;
				break;

			case architecture_t::x86:
				arch = architecture_t::x86;
				endian = endianess_t::little;
				ptrsize = 4;
				break;

			case architecture_t::arm64:
				arch = architecture_t::arm64;
				endian = endianess_t::little;
				ptrsize = 8;
				break;

			default:
				return FALSE;
		}

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
		auto level = get_log_level();
		dbg(L"Log level set to %s (%d)\n", std::get<1>(level), std::get<0>(level));
		return TRUE;
	}

	PWNAPI const std::tuple<pwn::log::log_level_t, const wchar_t*> get_log_level()
	{
		const wchar_t* str = L"";
		switch (__log_level)
		{
			case pwn::log::log_level_t::LOG_DEBUG:  
				str = L"LOG_LEVEL_DEBUG";
				break;

			case pwn::log::log_level_t::LOG_INFO:   
				str = L"LOG_LEVEL_INFO";
				break; 

			case pwn::log::log_level_t::LOG_WARNING:
				str = L"LOG_LEVEL_WARN";
				break;

			case pwn::log::log_level_t::LOG_ERROR: 
				str = L"LOG_LEVEL_ERROR";
				break;

			case pwn::log::log_level_t::LOG_CRITICAL:
				str = L"LOG_LEVEL_CRITICAL";
				break;
		}
		
		return std::tuple<pwn::log::log_level_t, const wchar_t*>  (__log_level, str);
	}

}