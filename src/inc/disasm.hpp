#pragma once

#if defined(PWN_INCLUDE_DISASSEMBLER)

#include "common.hpp"
#include "error.hpp"

constexpr uptr DefaultBaseAddress = 0x40000;

namespace pwn::Assembly
{
    struct Instruction
    {
        enum class Type
        {
            Lea,
            Mov,
            Jmp,
            Call,
            Ret,
            Add,
            Sub,
            Mul,
            Div,
            Test,
        };

        enum class Group : CBitMask
        {
            Arithmetic,
            ControlFlow,
            MemoryAccess,
        };
    };


    class Disassemble
    {
        public:
            Disassembler();
            
            Disassembler(pwn::Architecture const &arch);

            ///
            /// @brief Disassemble the next instruction in the buffer
            ///
            /// @param [in] bytes the code to disassemble
            ///
            /// @return
            ///
            Result<ZydisDecodedInstruction,dedInstruction>
            Disassemble(std::vector<u8> const& bytes);

            ///
            /// @brief
            ///
            /// @param [in] insn
            ///
            /// @return
            ///
            Result<std::string>
            Format(ZydisDecodedInstruction const& insn);

    /*
    friend std::ostream&
    operator<<(std::ostream& os, ZydisDecodedInstruction const& i)
    {
        os << std::format("{}", i);
        return os;
    }
    */
            ///
            /// @brief Print the disassembled buffer
            ///
            /// @param [in] bytes code the code to disassemble
            ///
            /// @return
            ///
            static void
            Print(std::vector<u8> const& bytes);


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
            usize m_Offset;
    };


template<>
struct std::formatter<ZydisDecodedInstruction, char> : std::formatter<std::string, char>
{
    auto
    format(ZydisDecodedInstruction const& insn, format_context& ctx)
    {
        ZydisFormatter fmt;
        std::string buffer;
        buffer.resize(256);

        ::ZydisFormatterInit(&fmt, ZYDIS_FORMATTER_STYLE_INTEL);
        ::ZydisFormatterFormatInstruction(&fmt, insn, buffer.data(), buffer.size(), DefaultBaseAddress);

        return formatter<string, char>::format(std::format("{}", buffer), ctx);
    }
};


} // namespace pwn::Assembly

#endif /* PWN_NO_DISASSEMBLER */
