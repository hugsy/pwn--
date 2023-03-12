#include <catch.hpp>

#include "Context.hpp"
#include "Disassembler.hpp"

using namespace pwn;

#if defined(PWN_INCLUDE_DISASSEMBLER)
TEST_CASE("Disassemble", "[Assembly]")
{
#ifdef PWN_DISASSEMBLE_X86
    SECTION("x64")
    {
        // x64 - nop; xor rax, rax; int3; ret
        const std::vector<u8> code = {0x90, 0x48, 0x31, 0xc0, 0xcc, 0xc3};

        // disassemble one insn (auto arch)
        {
            Context.Set("x64");
            Assembly::Disassembler d;

            auto res = d.Disassemble(code);
            REQUIRE(Success(res));

            auto const& insn = Value(res);
            REQUIRE(insn.length == 1);
        }

        // disassemble all
        {
            auto WantedArch = Architecture::Find("x64");
            Assembly::Disassembler d {WantedArch};

            d.SetOffset(0);
            auto res = d.DisassembleAll(code);
            REQUIRE(Success(res));

            auto const& insns = Value(res);
            REQUIRE(insns.size() == 4);
        }

        // disassemble until int3
        {
            auto WantedArch = Architecture::Find("x64");
            Assembly::Disassembler d {WantedArch};

            d.SetOffset(0);
            auto res = d.DisassembleUntil(
                code,
                [](auto const& i)
                {
                    return i.o.x86.mnemonic == ZydisMnemonic::ZYDIS_MNEMONIC_INT3;
                });
            REQUIRE(Success(res));

            auto const& insns = Value(res);
            REQUIRE(insns.size() == 2);
        }
    }

    SECTION("x86")
    {
        // x86 - nop; dec eax; xor eax, eax; int3; ret
        const std::vector<u8> code {0x90, 0x48, 0x31, 0xc0, 0xcc, 0xc3};

        // disassemble one insn
        {
            Context.Set("x86");
            Assembly::Disassembler d;

            auto res = d.Disassemble(code);
            REQUIRE(Success(res));

            auto const& insn = Value(res);
            REQUIRE(insn.length == 1);
        }

        // disassemble all
        {
            auto WantedArch = Architecture::Find("x86");
            Assembly::Disassembler d {WantedArch};

            d.SetOffset(0);
            auto res = d.DisassembleAll(code);
            REQUIRE(Success(res));

            auto const& insns = Value(res);
            REQUIRE(insns.size() == 5);
        }
    }
#endif // PWN_DISASSEMBLE_X86


#ifdef PWN_DISASSEMBLE_ARM64
    SECTION("arm64")
    {
        const std::vector<u8>
            code {0xc8, 0x18, 0x80, 0xd2, 0x01, 0xfd, 0x47, 0xd3, 0x20, 0xf8, 0x7f, 0xd3, 0xe2, 0x03, 0x1f, 0xaa};

        {
            Context.Set("arm64");
            Assembly::Disassembler d;

            auto res = d.Disassemble(code);
            REQUIRE(Success(res));

            auto const& insn = Value(res);
            REQUIRE(insn.length == 4);
        }


        {
            Context.Set("x64");
            auto a = Architecture::Find("arm64");
            auto d = Assembly::Disassembler(a);

            auto res = d.Disassemble(code);
            REQUIRE(Success(res));

            auto const& insn = Value(res);
            REQUIRE(insn.length == 4);
        }
    }
#endif // PWN_DISASSEMBLE_ARM64


    SECTION("Bad")
    {
        const std::vector<u8> code = {0xff, 0xff};
        for ( auto const& x : std::array<std::string, 2> {"x86", "x64"} )
        {
            auto WantedArch = Architecture::Find(x);
            Assembly::Disassembler d {WantedArch};
            REQUIRE(Failed(d.DisassembleAll(code)));
        }
    }
}
#endif
