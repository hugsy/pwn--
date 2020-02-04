#pragma once

#include "pwn.h"

#include <vector>


namespace pwn::assm
{
	BOOL PWNAPI assemble(_In_ const char* code, _In_ const size_t code_size, _Out_ std::vector<BYTE>& bytes);
	BOOL PWNAPI x64(_In_ const char* code, _In_ const size_t code_size, _Out_ std::vector<BYTE>& bytes);
	BOOL PWNAPI x86(_In_ const char* code, _In_ const size_t code_size, _Out_ std::vector<BYTE>& bytes);
}