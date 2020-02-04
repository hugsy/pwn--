#pragma once

#include "pwn.h"

#include <vector>
#include <string>


namespace pwn::disasm
{
	typedef struct _insn_t
	{
		uintptr_t address;
		uint16_t size;
		BYTE bytes[24];
		std::wstring mnemonic;
		std::wstring operands;
	} insn_t;

	_Success_(return) BOOL PWNAPI disassemble(_In_ const uint8_t* code, _In_ const size_t code_size, _Out_ std::vector<insn_t>& insns);
	_Success_(return) BOOL PWNAPI x64(_In_ const uint8_t* code, _In_ const size_t code_size, _Out_ std::vector<insn_t>& insns);
	_Success_(return) BOOL PWNAPI x86(_In_ const uint8_t* code, _In_ const size_t code_size, _Out_ std::vector<insn_t>& insns);
}
