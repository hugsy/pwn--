#include "disasm.h"

#include <capstone/capstone.h>

using namespace pwn::log;

#define CS_DEFAULT_BASE_ADDRESS 0x1000


namespace pwn::disasm
{

	BOOL x64(_In_ const uint8_t* code, _In_ const size_t code_size, _Out_ std::vector<BYTE> bytes)
	{
		csh handle;
		cs_insn* insn;
		size_t count;
		cs_arch arch;
		cs_mode mode;
		BOOL res = TRUE;

		switch (pwn::context::arch)
		{
		case pwn::context::arch_t::x64:
			arch = CS_ARCH_X86;
			mode = CS_MODE_64;
			break;

		default:
			err(L"unsupported architecture\n");
			break;
		}

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