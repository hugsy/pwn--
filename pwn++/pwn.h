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
#include "disasm.h"
#include "asm.h"
#include "process.h"
#include "registry.h"
#include "cpu.h"
#include "job.h"
#include "kernel.h"
#include "service.h"
#include "alpc.h"

