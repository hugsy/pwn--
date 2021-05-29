#include "disasm.h"

#include <capstone/capstone.h>

using namespace pwn::log;

#define CS_DEFAULT_BASE_ADDRESS 0x40000
#pragma warning(disable: 26812 ) // because of cs_arch & cs_mode,  TODO: fix


namespace pwn::disasm
{
    // private
    namespace
    {
        _Success_(return) 
        BOOL __build_insn(_In_ cs_insn _cs_insn, _Out_ insn_t& insn)
        {
            insn.address = _cs_insn.address;
            insn.size = _cs_insn.size;
            ::RtlCopyMemory(insn.bytes, _cs_insn.bytes, _cs_insn.size);
            insn.mnemonic = pwn::utils::to_widestring(_cs_insn.mnemonic);
            insn.operands = pwn::utils::to_widestring(_cs_insn.op_str); 
            return TRUE;
        }

        _Success_(return) 
        BOOL __disassemble(_In_ cs_arch arch, _In_ cs_mode mode, _In_ const uint8_t* code, _In_ const size_t code_size, _Out_ std::vector<insn_t>& insns)
        {
            csh handle;
            if (cs_open(arch, mode, &handle) != CS_ERR_OK)
            {
                err(L"cs_open() failed\n");
                return FALSE;
            }

            cs_insn* cs_insns;
            BOOL res = TRUE;
            size_t count = cs_disasm(handle, code, code_size, CS_DEFAULT_BASE_ADDRESS, 0, &cs_insns);
            if (count > 0)
            {
                for (size_t i = 0; i < count; i++)
                {
                    insn_t insn = { 0, };
                    if (__build_insn(cs_insns[i], insn))
                        insns.push_back(insn);
                    else
                    {
                        res = FALSE;
                        break;
                    }
                }

                cs_free(cs_insns, count);
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
    _Success_(return) 
    BOOL x86(_In_ const uint8_t* code, _In_ const size_t code_size, _Out_ std::vector<insn_t>& insns)
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
    _Success_(return) 
    BOOL x64(_In_ const uint8_t* code, _In_ const size_t code_size, _Out_ std::vector<insn_t>& insns)
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
    _Success_(return) 
    BOOL disassemble(_In_ const uint8_t* code, _In_ const size_t code_size, _Out_ std::vector<insn_t>& insns)
    {
        switch (pwn::context::arch)
        {
        case pwn::context::architecture_t::x86:
            return x86(code, code_size, insns);

        case pwn::context::architecture_t::x64:
            return x64(code, code_size, insns);

        default:
            err(L"unsupported architecture\n");
            break;
        }

        return FALSE;
    }
}