#include "Disassembler.hpp"

#ifdef PWN_INCLUDE_DISASSEMBLER

#include <expected>
#include <print>

#include "Context.hpp"


namespace pwn::Assembly
{

Disassembler::Disassembler() : Disassembler(Context.architecture)
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
        m_Valid = ZYAN_SUCCESS(::ZydisDecoderInit(
            &m_Decoder,
            ZydisMachineMode::ZYDIS_MACHINE_MODE_LONG_COMPAT_32,
            ZydisStackWidth::ZYDIS_STACK_WIDTH_32));
        m_Valid &= ZYAN_SUCCESS(::ZydisFormatterInit(&m_Formatter, ZYDIS_FORMATTER_STYLE_INTEL));
#else
        err(L"Not compiled with X86 support");
#endif //  PWN_DISASSEMBLE_X86
        break;

    case ArchitectureType::x64:
#ifdef PWN_DISASSEMBLE_X86
        m_Valid = ZYAN_SUCCESS(::ZydisDecoderInit(
            &m_Decoder,
            ZydisMachineMode::ZYDIS_MACHINE_MODE_LONG_64,
            ZydisStackWidth::ZYDIS_STACK_WIDTH_64));
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
        return Err(Error::NotInitialized);
    }

    if ( bytes.data() != m_Buffer || bytes.size() != m_BufferSize )
    {
        m_Buffer     = (u8*)bytes.data();
        m_BufferSize = bytes.size();
        SetOffset(0);
    }

    if ( m_BufferSize < m_BufferOffset )
    {
        return Err(Error::BufferTooSmall);
    }

    usize Left = m_BufferSize - m_BufferOffset;
    if ( Left > m_BufferSize )
    {
        return Err(Error::OverflowError);
    }

    if ( Left == 0 )
    {
        return Err(Error::NoMoreData);
    }

    Instruction insn {};

    switch ( m_Architecture )
    {
#ifdef PWN_DISASSEMBLE_X86
    case ArchitectureType::x86:
    case ArchitectureType::x64:
    {
        // ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT] {};

        if ( !ZYAN_SUCCESS(::ZydisDecoderDecodeFull(
                 &m_Decoder,
                 &bytes[m_BufferOffset],
                 Left,
                 &insn.o.x86.insn,
                 insn.o.x86.operands)) )
        {
            return Err(Error::ExternalApiCallFailed);
        }

        assert(insn.o.x86.insn.length < sizeof(insn.bytes));
        insn.length = insn.o.x86.insn.length;
        ::memcpy(&insn.bytes, &insn.o.x86.insn.raw, insn.length);
        break;
    }
#endif // PWN_DISASSEMBLE_X86

#ifdef PWN_DISASSEMBLE_ARM64
    case ArchitectureType::arm64:
    {
        if ( Left < 4 )
        {
            return Err(Error::InvalidInput);
        }

        const u32 insword = *((u32*)&bytes[m_BufferOffset]);
        if ( ::aarch64_decompose(insword, &insn.o.arm64, 0) != 0 )
        {
            return Err(Error::ExternalApiCallFailed);
        }

        insn.length = sizeof(u32);
        break;
    }
#endif // PWN_DISASSEMBLE_ARM64

    default:
        return Err(Error::InvalidInput);
    }

    m_BufferOffset += insn.length;

    return Ok(insn);
}

Result<Instructions>
Disassembler::DisassembleAll(std::vector<u8> const& Bytes)
{
    Instructions insns;

    while ( true )
    {
        auto res = Disassemble(Bytes);
        if ( Failed(res) )
        {
            if ( res.error() == Error::NoMoreData )
            {
                break;
            }

            return Err(res.error());
        }

        insns.push_back(Value(res));
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
        // ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT] {};
        if ( !ZYAN_SUCCESS(ZydisFormatterFormatInstruction(
                 &m_Formatter,
                 &insn.o.x86.insn,
                 insn.o.x86.operands,
                 insn.o.x86.insn.operand_count_visible,
                 buffer,
                 sizeof(buffer),
                 Address,
                 ZYAN_NULL)) )
        {
            return Err(Error::ExternalApiCallFailed);
        }

        break;
    }
#endif // PWN_DISASSEMBLE_X86

#ifdef PWN_DISASSEMBLE_ARM64
    case ArchitectureType::arm64:
    {
        // TODO: hack for now
        if ( ::aarch64_decompose(insn.o.arm64.insword, &insn.o.arm64, Address) != 0 )
        {
            return Err(Error::ExternalApiCallFailed);
        }

        if ( ::aarch64_disassemble(&insn.o.arm64, buffer, sizeof(buffer)) != 0 )
        {
            return Err(Error::ExternalApiCallFailed);
        }

        break;
    }
#endif // PWN_DISASSEMBLE_ARM64

    default:
        return Err(Error::InvalidInput);
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
    auto disArch = arch.value_or(Context.architecture);
    Disassembler dis {disArch};
    auto res = dis.DisassembleAll(bytes);
    if ( Failed(res) )
    {
        return;
    }

    std::vector<Instruction> insns = Value(res);
    for ( auto& insn : insns )
    {
        auto res = dis.Format(insn, DefaultBaseAddress);
        if ( Failed(res) )
        {
            return;
        }

        std::println("{}", Value(res));
    }
}


#ifdef PWN_DISASSEMBLE_X86
void
Disassembler::X64(std::vector<u8> const& bytes)
{
    Disassembler::Print(bytes, Architectures[ArchitectureType::x64]);
}


void
Disassembler::X86(std::vector<u8> const& bytes)
{
    Disassembler::Print(bytes, Architectures[ArchitectureType::x86]);
}
#endif // PWN_DISASSEMBLE_X86

#ifdef PWN_DISASSEMBLE_ARM64
void
Disassembler::ARM64(std::vector<u8> const& bytes)
{
    Disassembler::Print(bytes, Architectures[ArchitectureType::arm64]);
}
#endif

} // namespace pwn::Assembly

#endif // PWN_INCLUDE_DISASSEMBLER
