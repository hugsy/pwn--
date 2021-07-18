#pragma once

#include "common.h"


namespace pwn
{
	PWNAPI const wchar_t* version();
	PWNAPI const std::tuple<WORD, WORD> version_info();
}


#include "utils.h"
#include "context.h"
#include "log.h"
#include "system.h"
#ifndef PWN_NO_DISASSEMBLER
#include "disasm.h"
#endif
#ifndef PWN_NO_ASSEMBLER
#include "asm.h"
#endif // !PWN_NO_ASSEMBLER
#include "process.h"
#include "thread.h"
#include "registry.h"
#include "cpu.h"
#include "job.h"
#include "kernel.h"
#include "service.h"
#include "alpc.h"
#include "fs.h"
#include "rpc.h"
#include "crypto.h"
#include "tube.h"


