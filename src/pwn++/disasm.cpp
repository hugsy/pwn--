#include "disasm.hpp"

#ifndef PWN_NO_DISASSEMBLER
#include <Zydis/Zydis.h>

using namespace pwn::log;

extern struct pwn::globals_t pwn::globals;


namespace pwn::disasm
{
// private
namespace
{
std::vector<std::wstring>
disassemble_to_string(
    _In_ ZydisMachineMode arch,
    _In_ ZydisAddressWidth mode,
    _In_ const u8* code,
    _In_ const size_t code_size)
{
    std::vector<std::wstring> insns;
    ZydisDecoder decoder;
    ZydisDecoderInit(&decoder, arch, mode);

    ZydisFormatter formatter;
    ZydisFormatterInit(&formatter, ZYDIS_FORMATTER_STYLE_INTEL);

    ZyanU64 runtime_address = DEFAULT_BASE_ADDRESS;
    ZyanUSize offset        = 0;
    const ZyanUSize length  = sizeof(code);
    ZydisDecodedInstruction instruction;

    while ( ZYAN_SUCCESS(ZydisDecoderDecodeBuffer(&decoder, code + offset, length - offset, &instruction)) )
    {
        char buffer[256];
        ZydisFormatterFormatInstruction(&formatter, &instruction, buffer, sizeof(buffer), runtime_address);

        insns.push_back(pwn::utils::to_widestring(buffer));

        offset += instruction.length;
        runtime_address += instruction.length;

        offset += instruction.length;
        runtime_address += instruction.length;
    }

    return insns;
}

void
print_disassembled_code(
    _In_ ZydisMachineMode arch,
    _In_ ZydisAddressWidth mode,
    _In_ const u8* code,
    _In_ const size_t code_size)
{
    auto insns = disassemble_to_string(arch, mode, code, code_size);
    for ( auto const& insn : insns )
    {
        ok(L"%s", insn);
    }
}
} // namespace


/**
 * @brief x86 specific disassembly function
 *
 * @param [in] code code the code to disassemble
 * @param [in] code_size code_size is the size of code
 *
 * @return
 */
void
x86(_In_ const u8* code, _In_ const size_t code_size)
{
    return print_disassembled_code(ZYDIS_MACHINE_MODE_LONG_COMPAT_32, ZYDIS_ADDRESS_WIDTH_32, code, code_size);
}


/**
 * @brief x64 specific disassembly function
 *
 * @param [inout] code code the code to disassemble
 * @param [inout] code_size code_size is the size of code
 *
 * @return
 */
void
x64(_In_ const u8* code, _In_ const size_t code_size)
{
    return print_disassembled_code(ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_ADDRESS_WIDTH_64, code, code_size);
}


/**
 * @brief Generic function for disassemble code based on the context
 *
 * @param [inout] code code the code to disassemble
 * @param [inout] code_size code_size is the size of code
 *
 * @return
 */
void
disassemble(_In_ const u8* code, _In_ const size_t code_size)
{
    switch ( pwn::globals.architecture->id() )
    {
    case ArchitectureType::x86:
        return x86(code, code_size);

    case ArchitectureType::x64:
        return x64(code, code_size);

    default:
        break;
    }

    throw std::runtime_error("unsupported architecture\n");
}
} // namespace pwn::disasm

#endif /* PWN_NO_DISASSEMBLER */
