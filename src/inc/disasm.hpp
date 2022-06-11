#pragma once

#if defined(PWN_INCLUDE_DISASSEMBLER)

#include "pwn.hpp"

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

} // namespace pwn::disasm

#endif /* PWN_NO_DISASSEMBLER */
