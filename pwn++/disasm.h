#pragma once

#include "pwn.h"

#include <vector>



namespace pwn::disasm
{
	BOOL PWNAPI disassemble(_In_ const uint8_t* code, _In_ const size_t code_size, _Out_ std::vector<BYTE> insns);
	BOOL PWNAPI x64(_In_ const uint8_t* code, _In_ const size_t code_size, _Out_ std::vector<BYTE> insns);
	BOOL PWNAPI x86(_In_ const uint8_t* code, _In_ const size_t code_size, _Out_ std::vector<BYTE> insns);
}
