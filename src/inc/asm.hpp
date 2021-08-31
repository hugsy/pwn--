#pragma once

#include "pwn.hpp"

#ifndef PWN_NO_ASSEMBLER
namespace pwn::assm
{
    _Success_(return) bool PWNAPI assemble(_In_ const char* code, _In_ const size_t code_size, _Out_ std::vector<u8>& bytes);
    _Success_(return) bool PWNAPI x64(_In_ const char* code, _In_ const size_t code_size, _Out_ std::vector<u8>& bytes);
    _Success_(return) bool PWNAPI x86(_In_ const char* code, _In_ const size_t code_size, _Out_ std::vector<u8>& bytes);

    _Success_(return) PWNAPI std::vector<u8> assemble(_In_ const char* code, _In_ const size_t code_size);
    _Success_(return) PWNAPI std::vector<u8> x64(_In_ const char* code, _In_ const size_t code_size);
    _Success_(return) PWNAPI std::vector<u8> x86(_In_ const char* code, _In_ const size_t code_size);
}

#endif /* !PWN_NO_ASSEMBLER */