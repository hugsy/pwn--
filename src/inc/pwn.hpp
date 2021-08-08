#pragma once

#include <mutex>
#include <thread>

#include "common.hpp"


namespace pwn
{
struct globals_t
{
    std::thread m_backdoor_thread;
    std::vector<u32> m_admin_thread_ids {};
    u64 m_seed = 0;
    std::mutex m_console_mutex {};
};

extern struct globals_t globals;

PWNAPI auto
version() -> const wchar_t*;

PWNAPI auto
version_info() -> const std::tuple<WORD, WORD>;
} // namespace pwn


/**
 *
 * Common namespace definition
 *
 */

/// namespace pwn::context
#include "context.hpp"

/// namespace pwn::log
#include "log.hpp"

/// namespace pwn::utils
#include "utils.hpp"


/// namespace pwn::assm
#ifndef PWN_NO_DISASSEMBLER
#include "disasm.hpp"
#endif
#ifndef PWN_NO_ASSEMBLER
#include "asm.hpp"
#endif // !PWN_NO_ASSEMBLER


/**
 *
 * Windows namespace
 *
 */

/// namespace pwn::win::system
#include "win/system.hpp"

/// namespace pwn::win::process
#include "win/process.hpp"

/// namespace pwn::win::thread
#include "win/thread.hpp"

/*
/// namespace pwn::registry
#include "registry.hpp"

/// namespace pwn::cpu
#include "cpu.hpp"

/// namespace pwn::job
#include "job.hpp"

/// namespace pwn::kernel
#include "kernel.hpp"

/// namespace pwn::service
#include "service.hpp"

/// namespace pwn::rpc
#include "fs.hpp"

/// namespace pwn::windows::alpc
#include "alpc.hpp"

/// namespace pwn::windows::rpc
#include "rpc.hpp"

/// namespace pwn::crypto
#include "crypto.hpp"

// namespace pwn::backdoor
#include "backdoor.hpp"

*/


/**
 *
 * Linux namespace
 *
 */
// todo
/// namespace pwn::linux::system
// #include "linux/system.hpp"


//
// namespace pwn::ctf
//

/**
 *
 * CTF namespace
 *
 */

// #include "tube.hpp"
