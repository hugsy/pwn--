#include "disasm.hpp"

#include "pwn.hpp"


#ifdef PWN_INCLUDE_DISASSEMBLER

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
    m_BufferOffset {0}
{
    switch ( arch.id )
    {
    case ArchitectureType::x86:
#ifdef PWN_DISASSEMBLE_X86
        m_Valid =
            ZYAN_SUCCESS(::ZydisDecoderInit(&m_Decoder, ZYDIS_MACHINE_MODE_LONG_COMPAT_32, ZYDIS_ADDRESS_WIDTH_32));
#else
        err(L"Not compiled with X86 support");
#endif //  PWN_DISASSEMBLE_X86
        break;

    case ArchitectureType::x64:
#ifdef PWN_DISASSEMBLE_X86
        m_Valid = ZYAN_SUCCESS(::ZydisDecoderInit(&m_Decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_ADDRESS_WIDTH_64));
#else
        err(L"Not compiled with X64 support");
#endif //  PWN_DISASSEMBLE_X86
        break;

    case ArchitectureType::arm64:
#ifdef PWN_DISASSEMBLE_ARM64

#endif
        break;

    default:
        err(L"Unknown/unsupported architecture");
        return;
    }

    if ( !m_Valid )
    {
        err(L"Disassembler initialization failed.");
        return;
    }

#ifdef PWN_DISASSEMBLE_X86
    m_Valid = ZYAN_SUCCESS(::ZydisFormatterInit(&m_Formatter, ZYDIS_FORMATTER_STYLE_INTEL));
#endif //  PWN_DISASSEMBLE_X86
}


Disassembler::~Disassembler()
{
    if ( !m_Valid )
    {
        return;
    }
}

void
Disassembler::SetOffset(usize newOffset)
{
    if ( newOffset > m_BufferSize )
    {
        return;
    }

    m_BufferOffset = newOffset;
}

Result<Instruction>
Disassembler::Disassemble(std::vector<u8> const& bytes)
{
    if ( !m_Valid )
    {
        return Err(ErrorCode::NotInitialized);
    }

    if ( bytes.data() != m_Buffer || bytes.size() != m_BufferSize )
    {
        m_Buffer     = (u8*)bytes.data();
        m_BufferSize = bytes.size();
        SetOffset(0);
    }

    if ( m_BufferSize < m_BufferOffset )
    {
        return Err(ErrorCode::BufferTooSmall);
    }

    usize Left = m_BufferSize - m_BufferOffset;
    if ( Left > m_BufferSize )
    {
        return Err(ErrorCode::OverflowError);
    }

    if ( Left == 0 )
    {
        return Err(ErrorCode::NoMoreData);
    }

    Instruction insn {0};

#ifdef PWN_DISASSEMBLE_X86
    if ( !ZYAN_SUCCESS(::ZydisDecoderDecodeBuffer(&m_Decoder, &bytes[m_BufferOffset], Left, &insn)) )
    {
        return Err(ErrorCode::ExternalApiCallFailed);
    }
    m_BufferOffset += insn.length;
#endif

    return Ok(insn);
}

Result<std::vector<Instruction>>
Disassembler::DisassembleAll(std::vector<u8> const& Bytes)
{
    std::vector<Instruction> insns;

    while ( true )
    {
        auto res = Disassemble(Bytes);
        if ( Failed(res) )
        {
            auto e = Error(res);
            if ( e.code == ErrorCode::NoMoreData )
            {
                break;
            }

            return Err(e.code);
        }

        auto insn = Value(res);
        insns.push_back(std::move(insn));
    }

    return Ok(insns);
}


Result<std::string>
Disassembler::Format(Instruction const& insn, uptr Address)
{
    char buffer[1024] = {0};

#ifdef PWN_DISASSEMBLE_X86
    if ( !ZYAN_SUCCESS(::ZydisFormatterFormatInstruction(&m_Formatter, &insn, buffer, sizeof(buffer), Address)) )
    {
        return Err(ErrorCode::ExternalApiCallFailed);
    }
#endif // PWN_DISASSEMBLE_X86

    return Ok(std::string(buffer));
}


Result<std::vector<std::string>>
Disassembler::Format(std::vector<Instruction> const& insns, uptr addr)
{
    std::vector<std::string> insns_str;
    uptr current_addr = addr;

    for ( auto const& insn : insns )
    {
        auto res = Format(insn, current_addr);
        if ( Failed(res) )
        {
            break;
        }

#ifdef PWN_DISASSEMBLE_X86
        current_addr += insn.length;
#endif // PWN_DISASSEMBLE_X86

        insns_str.push_back(Value(res));
    }

    return Ok(insns_str);
}


void
Disassembler::Print(std::vector<u8> const& bytes, std::optional<Architecture> arch)
{
    auto disArch = arch.value_or(pwn::Context.architecture);
    Disassembler dis {disArch};
    auto res = dis.DisassembleAll(bytes);
    if ( Success(res) )
    {
        auto const& insns = Value(res);
        for ( auto const& insn : insns )
        {
            auto fmtInsn = dis.Format(insn, DefaultBaseAddress);
            if ( Success(fmtInsn) )
            {
                std::cout << Value(fmtInsn) << std::endl;
            }
        }
    }
}


#ifdef PWN_DISASSEMBLE_X86
void
Disassembler::X64(std::vector<u8> const& bytes)
{
    Disassembler::Print(bytes, Architectures[0].second);
}


void
Disassembler::X86(std::vector<u8> const& bytes)
{
    Disassembler::Print(bytes, Architectures[1].second);
}
#endif // PWN_DISASSEMBLE_X86

#ifdef PWN_DISASSEMBLE_ARM64
void
Disassembler::ARM64(std::vector<u8> const& bytes)
{
    Disassembler::Print(bytes, Architectures[2].second);
}
#endif

} // namespace pwn::Assembly

#endif // PWN_INCLUDE_DISASSEMBLER
