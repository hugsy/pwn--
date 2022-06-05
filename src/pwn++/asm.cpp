#include "asm.hpp"

#if defined(PWN_INCLUDE_ASSEMBLER)

// #include <stdexcept>

// using namespace pwn::log;

// #if defined(_MSC_VER)
// #pragma warning(disable: 26812 ) // because of ks_arch & ks_mode,  TODO: fix
// #endif

// namespace pwn::assm
// {

//     // private
//     namespace
//     {
//         _Success_(return)
//         bool __assemble(_In_ ks_arch arch, _In_ ks_mode mode, _In_ const char* code, _In_ const size_t code_size,
//         _Out_ std::vector<u8>& bytes)
//         {
//             ks_engine* ks;
//             size_t count, size;
//             u8* assembled;

//             UnusedParameter(code_size);

//             if (ks_open(arch, mode, &ks) != KS_ERR_OK)
//             {
//                 err(L"ks_open() failed\n");
//                 return false;
//             }

//             bool res = true;
//             do
//             {
//                 if (ks_asm(ks, code, 0, &assembled, &size, &count) != KS_ERR_OK)
//                 {
//                     err(L"ks_asm() failed: count=%lu, error=%u\n", count, ks_errno(ks));
//                     res = false;
//                     break;
//                 }

//                 if (size == 0)
//                 {
//                     res = false;
//                 }
//                 else
//                 {
//                     for (size_t i = 0; i < size; i++)
//                         bytes.push_back(assembled[i]);
//                 }

//                 ks_free(assembled);
//             }
//             while (0);

//             ks_close(ks);
//             return res;
//         }
//     }


//     /*++
//     Description:

//         x86 specific assembly function

//     Arguments:

//         - code the code to disassemble
//         - code_size is the size of code
//         - insns is a vector of instructions

//     Returns:

//         TRUE on success, else FALSE
//     --*/
//     _Success_(return)
//     bool PWNAPI x86(_In_ const char* code, _In_ const size_t code_size, _Out_ std::vector<u8>& bytes)
//     {
//         return __assemble(KS_ARCH_X86, KS_MODE_32, code, code_size, bytes);
//     }


//     std::vector<u8> PWNAPI x86(_In_ const char* code, _In_ const size_t code_size)
//     {
//         std::vector<u8> res;
//         __assemble(KS_ARCH_X86, KS_MODE_32, code, code_size, res);
//         return res;
//     }


//     /*++
// Description:

//     x64 specific assembly function

// Arguments:

//     - code the code to disassemble
//     - code_size is the size of code
//     - insns is a vector of instructions

// Returns:

//     TRUE on success, else FALSE
// --*/
//     _Success_(return)
//     bool PWNAPI x64(_In_ const char* code, _In_ const size_t code_size, _Out_ std::vector<u8>& bytes)
//     {
//         return __assemble(KS_ARCH_X86, KS_MODE_64, code, code_size, bytes);
//     }


//     std::vector<u8> PWNAPI x64(_In_ const char* code, _In_ const size_t code_size)
//     {
//         std::vector<u8> res;
//         __assemble(KS_ARCH_X86, KS_MODE_64, code, code_size, res);
//         return res;
//     }


//     /*++
//     Description:

//         Generic function for disassemble code based on the context

//     Arguments:

//         - code the code to disassemble
//         - code_size is the size of code
//         - insns is a vector of instructions

//     Returns:

//         TRUE on success, else FALSE
//     --*/
//     _Success_(return)
//     bool PWNAPI assemble(_In_ const char* code, _In_ const size_t code_size, _Out_ std::vector<u8>& bytes)
//     {
//         switch (pwn::context::arch)
//         {
//         case Architectures::x86:
//             return x86(code, code_size, bytes);

//         case Architectures::x64:
//             return x64(code, code_size, bytes);

//         default:
//             err(L"unsupported Architectures\n");
//             break;
//         }

//         return false;
//     }


//     std::vector<u8> assemble(_In_ const char* code, _In_ const size_t code_size)
//     {
//         switch (pwn::context::arch)
//         {
//             case Architectures::x86:
//                 return x86(code, code_size);

//             case Architectures::x64:
//                 return x64(code, code_size);

//             default:
//                 throw std::runtime_error("unsupported Architectures");
//                 break;
//         }
//     }
// }


#endif /* !PWN_NO_ASSEMBLER */
