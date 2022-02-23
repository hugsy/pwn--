#pragma once

#ifndef PWN_NO_DISASSEMBLER

#include "pwn.hpp"

#include <vector>
#include <string>

#define DEFAULT_BASE_ADDRESS 0x40000

namespace pwn::disasm
{
    PWNAPI
    void
    disassemble(_In_ const u8* code, _In_ const size_t code_size);

    PWNAPI
    void
    x64(_In_ const u8* code, _In_ const size_t code_size);

    PWNAPI
    void
    x86(_In_ const u8* code, _In_ const size_t code_size);

}

#endif /* PWN_NO_DISASSEMBLER */
