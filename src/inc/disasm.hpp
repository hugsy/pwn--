#pragma once

#ifndef PWN_NO_DISASSEMBLER

#include "pwn.hpp"

#include <vector>
#include <string>


namespace pwn::disasm
{
    typedef struct _insn_t
    {
        uintptr_t address;
        uint16_t size;
        u8 bytes[24];
        std::wstring mnemonic;
        std::wstring operands;
    } insn_t;

    _Success_(return) bool PWNAPI disassemble(_In_ const u8* code, _In_ const size_t code_size, _Out_ std::vector<insn_t>& insns);
    _Success_(return) bool PWNAPI x64(_In_ const u8* code, _In_ const size_t code_size, _Out_ std::vector<insn_t>& insns);
    _Success_(return) bool PWNAPI x86(_In_ const u8* code, _In_ const size_t code_size, _Out_ std::vector<insn_t>& insns);
}

#endif /* PWN_NO_DISASSEMBLER */
