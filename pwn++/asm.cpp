#include "asm.h"

#include <keystone/keystone.h>

using namespace pwn::log;

#define CS_DEFAULT_BASE_ADDRESS 0x40000


namespace pwn::assm
{

    // private
    namespace 
    {
        BOOL __assemble(_In_ ks_arch arch, _In_ ks_mode mode, _In_ const char* code, _In_ const size_t code_size, _Out_ std::vector<BYTE>& bytes)
        {
            ks_engine* ks;
            size_t count, size;
            PBYTE assembled;
            BOOL res = TRUE;

            if (ks_open(arch, mode, &ks) != KS_ERR_OK) 
            {
                err(L"ks_open() failed\n");
                return FALSE;
            }

            if (ks_asm(ks, code, 0, &assembled, &size, &count) != KS_ERR_OK)
            {
                err(L"ks_asm() failed: count=%lu, error=%u\n", count, ks_errno(ks));
                return FALSE;
            }

            info(L"asm size=%d count=%d\n", size, count);

            for (size_t i = 0; i < size; i++)
                bytes.push_back(assembled[i]);

            ks_free(assembled);
            ks_close(ks);
            return TRUE;
        }
    }


    /*++
    Description:

        x86 specific assembly function

    Arguments:

        - code the code to disassemble
        - code_size is the size of code
        - insns is a vector of instructions

    Returns:

        TRUE on success, else FALSE
    --*/
	BOOL PWNAPI x86(_In_ const char* code, _In_ const size_t code_size, _Out_ std::vector<BYTE>& bytes)
	{
        return __assemble(KS_ARCH_X86, KS_MODE_32, code, code_size, bytes);
	}



    /*++
Description:

    x64 specific assembly function

Arguments:

    - code the code to disassemble
    - code_size is the size of code
    - insns is a vector of instructions

Returns:

    TRUE on success, else FALSE
--*/
    BOOL PWNAPI x64(_In_ const char* code, _In_ const size_t code_size, _Out_ std::vector<BYTE>& bytes)
    {
        return __assemble(KS_ARCH_X86, KS_MODE_64, code, code_size, bytes);
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
    BOOL PWNAPI assemble(_In_ const char* code, _In_ const size_t code_size, _Out_ std::vector<BYTE>& bytes)
    {
        switch (pwn::context::arch)
        {
        case pwn::context::arch_t::x86:
            return x86(code, code_size, bytes);

        case pwn::context::arch_t::x64:
            return x64(code, code_size, bytes);

        default:
            err(L"unsupported architecture\n");
            return FALSE;
        }

        err(L"UNREACHABLE\n");
        return FALSE;
    }
}