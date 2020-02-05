#pragma once

#include "common.h"
#include "log.h"

namespace pwn::context
{
    enum class arch_t 
    {
        x86,
        x64,
        arm,
        arm_thumb,
        arm64,
        mips
    };

    extern PWNAPI arch_t arch;
    extern PWNAPI pwn::log::log_level_t log_level = pwn::log::log_level_t::LOG_INFO;
}