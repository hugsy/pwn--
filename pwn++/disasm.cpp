#include "disasm.h"

#include <capstone/capstone.h>

using namespace pwn::log;

#define CS_DEFAULT_BASE_ADDRESS 0x40000


namespace pwn::disasm
{
	// private
	namespace
	{
		BOOL __disassemble(_In_ cs_arch arch, _In_ cs_mode mode, _In_ const uint8_t* code, _In_ const size_t code_size, _Out_ std::vector<BYTE> insns)
		{
			csh handle;
			cs_insn* insn;
			size_t count;
			BOOL res = TRUE;

			if (cs_open(arch, mode, &handle) != CS_ERR_OK)
			{
				err(L"cs_open() failed\n");
				return FALSE;
			}

			count = cs_disasm(handle, code, code_size, CS_DEFAULT_BASE_ADDRESS, 0, &insn);
			if (count > 0)
			{
				size_t i;
				for (i = 0; i < count; i++)
				{
					ok(L"0x%08x:\t%S\t\t%S\n", insn[i].address, insn[i].mnemonic, insn[i].op_str);
				}

				cs_free(insn, count);
				res = TRUE;
			}
			else
			{
				err(L"Failed to disassemble given code!\n");
				res = FALSE;
			}

			cs_close(&handle);
			return res;
		}
	}


	/*++
	Description:

		x86 specific disassembly function

	Arguments:

		- code the code to disassemble
		- code_size is the size of code
		- insns is a vector of instructions

	Returns:

		TRUE on success, else FALSE
	--*/
	BOOL x86(_In_ const uint8_t* code, _In_ const size_t code_size, _Out_ std::vector<BYTE> insns)
	{
		return __disassemble(CS_ARCH_X86, CS_MODE_32, code, code_size, insns);
	}


	/*++
	Description:

		x64 specific disassembly function

	Arguments:

		- code the code to disassemble
		- code_size is the size of code
		- insns is a vector of instructions

	Returns:

		TRUE on success, else FALSE
	--*/
	BOOL x64(_In_ const uint8_t* code, _In_ const size_t code_size, _Out_ std::vector<BYTE> insns)
	{
		return __disassemble(CS_ARCH_X86, CS_MODE_64, code, code_size, insns);
	}


	/*++
	Description:

		Generic function for disassemble code based on the context

	Arguments:

		- code the code to disassemble
		- code_size is the size of code
		- insns is a vector of instructions

	Returns:

		TRUE on success, else FALSE
	--*/
	BOOL disassemble(_In_ const uint8_t* code, _In_ const size_t code_size, _Out_ std::vector<BYTE> insns)
	{
		switch (pwn::context::arch)
		{
		case pwn::context::arch_t::x86:
			return x86(code, code_size, insns);

		case pwn::context::arch_t::x64:
			return x64(code, code_size, insns);

		default:
			err(L"unsupported architecture\n");
			return FALSE;
		}

		err(L"UNREACHABLE\n");
		return FALSE;
	}
}