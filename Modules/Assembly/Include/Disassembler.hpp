#pragma once

// clang-format off
#include "Common.hpp"
#include "Error.hpp"
#include "Architecture.hpp"
// clang-format on

#ifdef PWN_INCLUDE_DISASSEMBLER

#if defined(PWN_DISASSEMBLE_X86)
#include <Zydis.h>
#endif // PWN_DISASSEMBLE_X86

#if defined(PWN_DISASSEMBLE_ARM64)
#include <arm64dis.h>
#endif // PWN_DISASSEMBLE_ARM64

namespace pwn::Assembly
{

constexpr uptr DefaultBaseAddress = 0x0014'0000;

struct Instruction
{
    union
    {
#ifdef PWN_DISASSEMBLE_X86
        struct
        {
            ::ZydisDecodedInstruction insn;
            ::ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT] {};
        } x86;
#endif // PWN_DISASSEMBLE_X86

#ifdef PWN_DISASSEMBLE_ARM64
        ::Instruction arm64;
#endif // PWN_DISASSEMBLE_ARM64
    } o;

    u8 bytes[24];
    usize length;
    uptr address;
};


class Disassembler
{
public:
    ///
    ///@brief Construct a new Disassembler object using the global context architecture
    ///
    Disassembler();

    ///
    ///@brief Construct a new Disassembler object for a specific architecture
    ///
    ///@param arch
    ///
    Disassembler(Architecture const& arch);

    ///
    ///@brief Destroy the Disassembler:: Disassembler object
    ///
    ///
    ~Disassembler();


    ///
    ///@brief (Re-)Set the offset with the buffer
    ///
    void SetOffset(usize);

    ///
    /// @brief Disassemble the next instruction in the buffer
    ///
    /// @param [in] bytes the code to disassemble
    ///
    /// @return
    ///
    Result<Instruction>
    Disassemble(std::vector<u8> const& bytes);


    ///
    ///@brief Disassemble the given buffer until a condition is met
    ///
    ///@tparam N
    ///@param Bytes
    ///@param Pred
    ///@return Result<std::vector<Instruction>>
    ///
    template<typename N>
    Result<std::vector<Instruction>>
    DisassembleUntil(std::vector<u8> const& Bytes, N Pred)
    {
        std::vector<Instruction> insns;

        while ( true )
        {
            auto res = Disassemble(Bytes);
            if ( Failed(res) )
            {
                auto err = Error(res);
                if ( err.Code == ErrorCode::NoMoreData )
                {
                    break;
                }

                return err;
            }

            auto insn = Value(res);

            if ( Pred(insn) == true )
            {
                break;
            }

            insns.push_back(std::move(insn));
        }

        return Ok(insns);
    }


    ///
    ///@brief
    ///
    ///@param Bytes
    ///@return Result<std::vector<Instruction>>
    ///
    Result<std::vector<Instruction>>
    DisassembleAll(std::vector<u8> const& Bytes);


    ///
    /// @brief Format one instruction, binding to the given address
    ///
    /// @param [in] `insn`
    /// @param [in] `addr`
    ///
    /// @return `Result<std::string>`
    ///
    Result<std::string>
    Format(Instruction& insn, uptr addr);


    ///
    ///@brief Format a vector of instruction to string, with the given address as start address
    ///
    ///@param [in] `insns`
    ///@param [in] `addr`
    ///
    ///@return `Result<std::vector<std::string>>`
    ///
    Result<std::vector<std::string>>
    Format(std::vector<Instruction>& insns, uptr addr);


    ///
    /// @brief Print the disassembled buffer
    ///
    /// @param [in] bytes code the code to disassemble
    /// @param [inopt] arch the architecture to use to disassemble, if not provided, use from context
    ///
    /// @return
    ///
    static void
    Print(std::vector<u8> const& bytes, std::optional<Architecture> arch);

#ifdef PWN_DISASSEMBLE_X86
    ///
    /// @brief Print buffer as x64 disassembly
    ///
    /// @param [in] bytes code the code to disassemble
    ///
    /// @return
    ///
    static void
    X64(std::vector<u8> const& bytes);


    ///
    /// @brief Print buffer as x86 disassembly
    ///
    /// @param [in] bytes code the code to disassemble
    ///
    /// @return
    ///
    static void
    X86(std::vector<u8> const& bytes);
#endif // PWN_DISASSEMBLE_X86

#ifdef PWN_DISASSEMBLE_ARM64
    ///
    /// @brief Print buffer as ARM64 disassembly
    ///
    /// @param [in] bytes code the code to disassemble
    ///
    /// @return
    ///
    static void
    ARM64(std::vector<u8> const& bytes);
#endif

private:
#ifdef PWN_DISASSEMBLE_X86
    ZydisDecoder m_Decoder;
    ZydisFormatter m_Formatter;
#endif // PWN_DISASSEMBLE_X86

#ifdef PWN_DISASSEMBLE_ARM64
#endif // PWN_DISASSEMBLE_ARM64

    ArchitectureType m_Architecture;
    u8* m_Buffer;
    usize m_BufferSize;
    usize m_BufferOffset;
    bool m_Valid;
};


} // namespace pwn::Assembly
#endif // PWN_INCLUDE_DISASSEMBLER
