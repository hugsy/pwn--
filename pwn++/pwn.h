#pragma once

#include <thread>

#include "common.h"


namespace pwn
{
struct globals_t
{
    std::thread m_backdoor_thread;
    std::vector<u32> m_admin_thread_ids{};
    QWORD m_seed           = 0;
    HANDLE m_console_mutex = INVALID_HANDLE_VALUE;
};

extern struct globals_t globals;

PWNAPI auto
version() -> const wchar_t *;

PWNAPI auto
version_info() -> const std::tuple<WORD, WORD>;
} // namespace pwn


/// namespace pwn::utils
#include "utils.h"

/// namespace pwn::context
#include "context.h"

/// namespace pwn::log
#include "log.h"

/// namespace pwn::system
#include "system.h"

/// namespace pwn::assm
#ifndef PWN_NO_DISASSEMBLER
#include "disasm.h"
#endif
#ifndef PWN_NO_ASSEMBLER
#include "asm.h"
#endif // !PWN_NO_ASSEMBLER

/// namespace pwn::process
#include "process.h"

/// namespace pwn::thread
#include "thread.h"

/// namespace pwn::thread
#include "registry.h"

/// namespace pwn::cpu
#include "cpu.h"

/// namespace pwn::job
#include "job.h"

/// namespace pwn::kernel
#include "kernel.h"

/// namespace pwn::service
#include "service.h"

/// namespace pwn::rpc
#include "fs.h"

/// namespace pwn::windows::alpc
#include "alpc.h"

/// namespace pwn::windows::rpc
#include "rpc.h"

/// namespace pwn::crypto
#include "crypto.h"

/// namespace pwn::ctf
#include "tube.h"

// namespace pwn::backdoor
#include "backdoor.h"
