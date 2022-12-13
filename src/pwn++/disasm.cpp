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
        m_Valid &= ZYAN_SUCCESS(::ZydisFormatterInit(&m_Formatter, ZYDIS_FORMATTER_STYLE_INTEL));
#else
        err(L"Not compiled with X86 support");
#endif //  PWN_DISASSEMBLE_X86
        break;

    case ArchitectureType::x64:
#ifdef PWN_DISASSEMBLE_X86
        m_Valid = ZYAN_SUCCESS(::ZydisDecoderInit(&m_Decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_ADDRESS_WIDTH_64));
        m_Valid &= ZYAN_SUCCESS(::ZydisFormatterInit(&m_Formatter, ZYDIS_FORMATTER_STYLE_INTEL));
#else
        err(L"Not compiled with X64 support");
#endif //  PWN_DISASSEMBLE_X86
        break;

    case ArchitectureType::arm64:
#ifdef PWN_DISASSEMBLE_ARM64
        m_Valid = true;
#else
        err(L"Not compiled with ARM64 support");
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

    m_Architecture = arch.id;
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

    Instruction insn {};

    switch ( m_Architecture )
    {
#ifdef PWN_DISASSEMBLE_X86
    case ArchitectureType::x86:
    case ArchitectureType::x64:
    {
        if ( !ZYAN_SUCCESS(::ZydisDecoderDecodeBuffer(&m_Decoder, &bytes[m_BufferOffset], Left, &insn.o.x86)) )
        {
            return Err(ErrorCode::ExternalApiCallFailed);
        }

        assert(insn.o.x86.length < sizeof(insn.bytes));
        insn.length = insn.o.x86.length;
        ::memcpy(&insn.bytes, &insn.o.x86.raw, insn.length);
        break;
    }
#endif // PWN_DISASSEMBLE_X86

#ifdef PWN_DISASSEMBLE_ARM64
    case ArchitectureType::arm64:
    {
        if ( Left < 4 )
        {
            return Err(ErrorCode::InvalidInput);
        }

        const u32 insword = *((u32*)&bytes[m_BufferOffset]);
        if ( ::aarch64_decompose(insword, &insn.o.arm64, 0) != 0 )
        {
            return Err(ErrorCode::ExternalApiCallFailed);
        }

        insn.length = sizeof(u32);
        break;
    }
#endif // PWN_DISASSEMBLE_ARM64

    default:
        return Err(ErrorCode::InvalidInput);
    }

    m_BufferOffset += insn.length;

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
Disassembler::Format(Instruction& insn, uptr Address)
{
    char buffer[1024] = {0};

    switch ( m_Architecture )
    {
#ifdef PWN_DISASSEMBLE_X86
    case ArchitectureType::x86:
    case ArchitectureType::x64:
    {
        if ( !ZYAN_SUCCESS(
                 ::ZydisFormatterFormatInstruction(&m_Formatter, &insn.o.x86, buffer, sizeof(buffer), Address)) )
        {
            return Err(ErrorCode::ExternalApiCallFailed);
        }
    }
#endif // PWN_DISASSEMBLE_X86

#ifdef PWN_DISASSEMBLE_ARM64
    case ArchitectureType::arm64:
    {
        // TODO: hack for now
        if ( ::aarch64_decompose(insn.o.arm64.insword, &insn.o.arm64, Address) != 0 )
        {
            return Err(ErrorCode::ExternalApiCallFailed);
        }

        if ( ::aarch64_disassemble(&insn.o.arm64, buffer, sizeof(buffer)) != 0 )
        {
            return Err(ErrorCode::ExternalApiCallFailed);
        }
    }
#endif // PWN_DISASSEMBLE_ARM64

    default:
        return Err(ErrorCode::InvalidInput);
    }

    return Ok(std::string(buffer));
}


Result<std::vector<std::string>>
Disassembler::Format(std::vector<Instruction>& insns, uptr addr)
{
    std::vector<std::string> insns_str;
    uptr current_addr = addr;

    for ( auto& insn : insns )
    {
        auto res = Format(insn, current_addr);
        if ( Failed(res) )
        {
            break;
        }

        current_addr += insn.length;
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
        std::vector<Instruction> insns = Value(res);
        for ( auto& insn : insns )
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
    Disassembler::Print(bytes, Architectures["x64"]);
}


void
Disassembler::X86(std::vector<u8> const& bytes)
{
    Disassembler::Print(bytes, Architectures["x86"]);
}
#endif // PWN_DISASSEMBLE_X86

#ifdef PWN_DISASSEMBLE_ARM64
void
Disassembler::ARM64(std::vector<u8> const& bytes)
{
    Disassembler::Print(bytes, Architectures["arm64"]);
}
#endif

} // namespace pwn::Assembly

#endif // PWN_INCLUDE_DISASSEMBLER
