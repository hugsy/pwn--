#pragma once

// clang-format off
#include "common.hpp"
#include "error.hpp"
#include "architecture.hpp"
// clang-format on

#ifdef PWN_INCLUDE_DISASSEMBLER
#include <Zydis/Zydis.h>

constexpr uptr DefaultBaseAddress = 0x40000;

namespace pwn::Assembly
{
using Instruction = ZydisDecodedInstruction;

class Disassembler
{
public:
    Disassembler();

    Disassembler(Architecture const& arch);

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
                auto e = Error(res);
                if ( e.code == ErrorCode::NoMoreData )
                {
                    break;
                }

                return Err(e.code);
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
    Format(Instruction const& insn, uptr addr);


    ///
    ///@brief Format a vector of instruction to string, with the given address as start address
    ///
    ///@param [in] `insns`
    ///@param [in] `addr`
    ///
    ///@return `Result<std::vector<std::string>>`
    ///
    Result<std::vector<std::string>>
    Format(std::vector<Instruction> const& insns, uptr addr);


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


    ///
    /// @brief x64 specific disassembly function
    ///
    /// @param [in] bytes code the code to disassemble
    ///
    /// @return
    ///
    static void
    X64(std::vector<u8> const& bytes);


    ///
    /// @brief x86 specific disassembly function
    ///
    /// @param [in] bytes code the code to disassemble
    ///
    /// @return
    ///
    static void
    X86(std::vector<u8> const& bytes);


private:
    ZydisDecoder m_Decoder;
    ZydisMachineMode m_MachineMode;
    ZydisAddressWidth m_AddressWidth;
    ZydisFormatter m_Formatter;

    u8* m_Buffer;
    usize m_BufferSize;
    usize m_BufferOffset;
    bool m_Valid;
};


} // namespace pwn::Assembly

#endif // PWN_INCLUDE_DISASSEMBLER
