#pragma once

#include <mutex>
#include <ranges>
#include <thread>

#include "architecture.hpp"
#include "common.hpp"


/**
 *
 * Common namespace definition
 *
 */

// namespace pwn::log
#include "log.hpp"

// namespace pwn::context
#include "context.hpp"


// namespace pwn::utils
#include "utils.hpp"

/// namespace pwn::crypto
#include "crypto.hpp"

/// namespace pwn::assm & namespace pwn::disassm
#include "asm.hpp"
#include "disasm.hpp"


#ifdef __PWNLIB_WINDOWS_BUILD__
/**
 *
 * Windows namespace definition
 * -> pwn::win
 */

/// namespace pwn::win::system
#include "win32/system.hpp"

/// namespace pwn::win::process
#include "win32/process.hpp"

/// namespace pwn::win::thread
#include "win32/thread.hpp"

/// namespace pwn::win::cpu
#include "win32/cpu.hpp"

/// namespace pwn::win::registry
#include "win32/registry.hpp"

/// namespace pwn::win::kernel
#include "win32/kernel.hpp"

/// namespace pwn::win::job
#include "win32/job.hpp"

/*
/// namespace pwn::service
#include "service.hpp"

/// namespace pwn::rpc
#include "fs.hpp"

/// namespace pwn::windows::alpc
#include "alpc.hpp"

/// namespace pwn::windows::rpc
#include "rpc.hpp"

*/
// namespace pwn::backdoor
#include "backdoor.hpp"
#include "thread.hpp"


///
/// Aliasing pwn::ctf to the corresponding OS the lib was build for
///
namespace pwn::win::ctf
{
}

namespace pwn
{
/// `pwn::ctf` -> `pwn::win::ctf` for Windows
namespace ctf = win::ctf;
} // namespace pwn

#include "win32/ctf/remote.hpp"

#endif


#ifdef __PWNLIB_LINUX_BUILD__
/**
 *
 * Linux namespace definition
 *
 */
// namespace pwn::linux::system
#include "linux/system.hpp"

namespace pwn::linux::ctf
{
}
namespace pwn
{
/// `pwn::ctf` -> `pwn::linux::ctf` for Linux
namespace ctf = linux::ctf;
} // namespace pwn

#include "linux/ctf/remote.hpp"
#endif


/**
 *
 * Globals
 *
 */
namespace pwn
{
struct globals_t
{
    std::thread m_backdoor_thread;
    std::vector<u32> m_admin_thread_ids;
    u64 m_seed;
    std::mutex m_console_mutex;
    log::log_level_t log_level = log::log_level_t::LOG_INFO;

    Architecture architecture;
    Endianess endianess;
    usize ptrsize;
    usize instruction_size;

    globals_t()
    {
        m_seed = std::chrono::system_clock::now().time_since_epoch().count();
        std::srand(m_seed);
        set("x64");
    };

    void
    set(std::string_view const& type)
    {
        const std::string _t {type};
        set(pwn::utils::to_widestring(_t));
    }

    void
    set(std::wstring_view const& type)
    {
        try
        {
            architecture = lookup_architecture(type);
            endianess    = architecture.endian;
            ptrsize      = architecture.ptrsize;

            dbg(L"Selecting {}", architecture);
        }
        catch ( std::range_error const& e )
        {
            err(L"Invalid architecture '{}'. Value must be in:", type);
            for ( auto const& name : std::views::keys(Architectures) )
                std::wcout << L"- " << std::setw(9) << name << std::endl;
        }
    }

    void
    set(Endianess end)
    {
        endianess = end;
    }

    void
    set(log::log_level_t new_log_level)
    {
        log_level = new_log_level;
        if ( log_level == log::log_level_t::LOG_DEBUG )
        {
            dbg(L"Setting DEBUG log level");
        }
    }
};

///
/// @brief The global context information are stored in this global variable
///
extern PWNAPI struct globals_t globals;

PWNAPI auto
version() -> const wchar_t*;

PWNAPI auto
version_info() -> const std::tuple<u16, u16>;

} // namespace pwn
