#pragma once

#include <mutex>
#include <thread>

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

/// namespace pwn::assm
#ifndef PWN_NO_DISASSEMBLER
#include "disasm.hpp"
#endif

#ifndef PWN_NO_ASSEMBLER
#include "asm.hpp"
#endif // !PWN_NO_ASSEMBLER



#ifdef __PWNLIB_WINDOWS_BUILD__
/**
 *
 * Windows namespace definition
 *
 */

/// namespace pwn::win::system
#include "win/system.hpp"

/// namespace pwn::win::process
#include "win/process.hpp"

/// namespace pwn::win::thread
#include "win/thread.hpp"

/// namespace pwn::win::cpu
#include "win/cpu.hpp"

/// namespace pwn::win::registry
#include "win/registry.hpp"

/// namespace pwn::win::kernel
#include "win/kernel.hpp"

/// namespace pwn::win::job
#include "win/job.hpp"

/*
/// namespace pwn::service
#include "service.hpp"

/// namespace pwn::rpc
#include "fs.hpp"

/// namespace pwn::windows::alpc
#include "alpc.hpp"

/// namespace pwn::windows::rpc
#include "rpc.hpp"

// namespace pwn::backdoor
#include "backdoor.hpp"
*/



///
/// Aliasing pwn::ctf to the corresponding OS the lib was build for
///
namespace pwn::win::ctf{}

namespace pwn
{
    /// `pwn::ctf` -> `pwn::win::ctf` for Windows
    namespace ctf = win::ctf;
}

#include "win/ctf/remote.hpp"

#endif


#ifdef __PWNLIB_LINUX_BUILD__
/**
 *
 * Linux namespace definition
 *
 */
#ifdef linux
#undef linux
#endif

// namespace pwn::linux::system
#include "linux/system.hpp"

namespace pwn::linux::ctf{}
namespace pwn
{
    /// `pwn::ctf` -> `pwn::win::ctf` for Linux
    namespace ctf = ::pwn::linux::ctf;
}

//#include "win/ctf/remote.hpp"
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
};

extern struct globals_t globals;

PWNAPI auto
version() -> const wchar_t*;

PWNAPI auto
version_info() -> const std::tuple<u16, u16>;
} // namespace pwn