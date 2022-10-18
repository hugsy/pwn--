#ifdef PWN_INCLUDE_DISASSEMBLER
#include "disasm.hpp"

namespace log = pwn::log;

extern struct pwn::GlobalContext pwn::Context;


namespace pwn::Assembly
{

Disassembler::Disassembler() : Disassembler(pwn::Context.architecture)
{
}

Disassembler::Disassembler(Architecture const& arch) :
    m_Valid {false},
    m_Buffer {nullptr},
    m_BufferSize {0},
    m_Offset {0},
    m_StartAddress {DefaultBaseAddress}
{
    switch ( arch.id )
    {
    case ArchitectureType::x86:
        m_MachineMode  = ZYDIS_MACHINE_MODE_LONG_COMPAT_32;
        m_AddressWidth = ZYDIS_ADDRESS_WIDTH_32;
        break;

    case ArchitectureType::x64:
        m_MachineMode  = ZYDIS_MACHINE_MODE_LONG_64;
        m_AddressWidth = ZYDIS_ADDRESS_WIDTH_64;
        break;

    default:
        err(L"Unknown/unsupported architecture");
        return;
    }

    ZyanStatus zStatus = ::ZydisDecoderInit(&m_Decoder, m_ZydisMachineMode, m_ZydisAddressWidth);
    if ( !ZYAN_SUCCESS(zStatus) )
    {
        return;
    }

    zStatus = ::ZydisFormatterInit(&m_Formatter, ZYDIS_FORMATTER_STYLE_INTEL);
    if ( !ZYAN_SUCCESS(zStatus) )
    {
        return;
    }

    m_Valid = true;
}


Result<ZydisDecodedInstruction>
Disassembler::Disassemble(std::vector<u8> const& bytes)
{
    if ( !m_Valid )
    {
        return Err(ErrorCode::NotInitialized);
    }

    if ( bytes.data() != m_Buffer || bytes.size() != m_BufferSize )
    {
        m_Buffer     = bytes.data();
        m_BufferSize = bytes.size();
        m_Offset     = 0;
    }

    if ( m_BufferSize < m_Offset )
    {
        return Err(ErrorCode::BufferTooSmall);
    }

    usize Left = m_BufferSize - m_Offset;
    if ( Left > m_BufferSize )
    {
        return Err(ErrorCode::OverflowError);
    }

    ZydisDecodedInstruction insn;
    if ( !ZYAN_SUCCESS(::ZydisDecoderDecodeBuffer(&m_Decoder, &bytes[m_Offset], Left, &insn)) )
    {
        return Err(ErrorCode::ExternalApiCallFailed);
    }

    m_Offset += insn.length;

    return Ok(insn);
}


Result<std::string>
Disassemble::Format(ZydisDecodedInstruction const& insn)
{
    std::string buffer;
    buffer.resize(256);

    if ( !ZYAN_SUCCESS(::ZydisFormatterFormatInstruction(&m_Formatter, insn, buffer.data(), buffer.size(), m_StartAddress+m_Offset))
    {
        return Err(ErrorCode::ExternalApiCallFailed);
    }

    return Ok(buffer);
}


void
Disassemble::X86(std::vector<u8> const& bytes)
{
    // return print_disassembled_code(ZYDIS_MACHINE_MODE_LONG_COMPAT_32, ZYDIS_ADDRESS_WIDTH_32, code, code_size);
}


void
Disassemble::X64(std::vector<u8> const& bytes)
{
    // return print_disassembled_code(ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_ADDRESS_WIDTH_64, code, code_size);
}


///
/// @brief Generic function for disassemble code based on the context
///
/// @param [in] code a vector of bytes to disassemble
///
/// @return
///
void
Disassemble::Print(std::vector<u8> const& bytes)
{
    Disassembler dis {pwn::Context.architecture};

    for ( auto const& insn : dis.Disassemble(bytes) )
    {
        ok(L"%s", insn);
    }
}
} // namespace pwn::Assembly

#endif // PWN_INCLUDE_DISASSEMBLER
