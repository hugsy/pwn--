#pragma once

#include "pwn.hpp"

#ifndef PWN_NO_ASSEMBLER
namespace pwn::assm
{
    _Success_(return) BOOL PWNAPI assemble(_In_ const char* code, _In_ const size_t code_size, _Out_ std::vector<BYTE>& bytes);
    _Success_(return) BOOL PWNAPI x64(_In_ const char* code, _In_ const size_t code_size, _Out_ std::vector<BYTE>& bytes);
    _Success_(return) BOOL PWNAPI x86(_In_ const char* code, _In_ const size_t code_size, _Out_ std::vector<BYTE>& bytes);

    _Success_(return) PWNAPI std::vector<BYTE> assemble(_In_ const char* code, _In_ const size_t code_size);
    _Success_(return) PWNAPI std::vector<BYTE> x64(_In_ const char* code, _In_ const size_t code_size);
    _Success_(return) PWNAPI std::vector<BYTE> x86(_In_ const char* code, _In_ const size_t code_size);
}

#endif /* !PWN_NO_ASSEMBLER */