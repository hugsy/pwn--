#include "context.hpp"
#include "log.hpp"
#include "pwn.hpp"

extern struct pwn::globals_t pwn::globals;

namespace pwn::context
{
    PWNAPI architecture_t arch = architecture_t::x64;
    PWNAPI endianess_t endian = endianess_t::little;
    PWNAPI u8 ptrsize = 8;

    auto set_architecture(_In_ architecture_t new_arch) -> bool
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
                return false;
        }

        dbg(L"new architecture set to %d (ptrsz=%d)\n", new_arch, ptrsize);
        // TODO: add hooks that triggers on arch change
        return true;
    }

    auto set_log_level(_In_ pwn::log::log_level_t new_level) -> bool
    {
        pwn::globals.log_level = new_level;
        auto level = get_log_level();
        dbg(L"Log level set to %s (%d)\n", std::get<1>(level), std::get<0>(level));
        return true;
    }

    PWNAPI auto get_log_level() -> const std::tuple<pwn::log::log_level_t, const wchar_t*>
    {
        const wchar_t* str = nullptr;
        switch (pwn::globals.log_level)
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

            default:
                throw std::range_error("invalid log level");
        }

        return std::tuple<pwn::log::log_level_t, const wchar_t*>  (globals.log_level, str);
    }

}