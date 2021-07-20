#pragma once

#include "common.h"


namespace pwn
{
	PWNAPI const wchar_t* version();
	PWNAPI const std::tuple<WORD, WORD> version_info();
}


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


