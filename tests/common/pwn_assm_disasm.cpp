#include <catch.hpp>
#include <pwn.hpp>


#if defined(PWN_INCLUDE_DISASSEMBLER)
TEST_CASE("Disassemble", "[pwn::Assembly]")
{
#ifdef PWN_DISASSEMBLE_X86
    SECTION("x64")
    {
        // x64 - nop; xor rax, rax; int3; ret
        const std::vector<u8> code = {0x90, 0x48, 0x31, 0xc0, 0xcc, 0xc3};

        // disassemble one insn (auto arch)
        {
            pwn::Context.set("x64");
            pwn::Assembly::Disassembler d;

            auto res = d.Disassemble(code);
            REQUIRE(Success(res));

            auto const& insn = Value(res);
            REQUIRE(insn.length == 1);
        }

        // disassemble all
        {
            auto WantedArch = Architecture::Find("x64");
            pwn::Assembly::Disassembler d {WantedArch};

            d.SetOffset(0);
            auto res = d.DisassembleAll(code);
            REQUIRE(Success(res));

            auto const& insns = Value(res);
            REQUIRE(insns.size() == 4);
        }

        // disassemble until int3
        {
            auto WantedArch = Architecture::Find("x64");
            pwn::Assembly::Disassembler d {WantedArch};

            d.SetOffset(0);
            auto res = d.DisassembleUntil(
                code,
                [](auto const& i)
                {
                    return i.mnemonic == ZydisMnemonic::ZYDIS_MNEMONIC_INT3;
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
            pwn::Context.set("x86");
            pwn::Assembly::Disassembler d;

            auto res = d.Disassemble(code);
            REQUIRE(Success(res));

            auto const& insn = Value(res);
            REQUIRE(insn.length == 1);
        }

        // disassemble all
        {
            auto WantedArch = Architecture::Find("x86");
            pwn::Assembly::Disassembler d {WantedArch};

            d.SetOffset(0);
            auto res = d.DisassembleAll(code);
            REQUIRE(Success(res));

            auto const& insns = Value(res);
            REQUIRE(insns.size() == 5);
        }
    }
#endif // PWN_DISASSEMBLE_X86

    SECTION("Bad")
    {
        const std::vector<u8> code = {0xff, 0xff};
        for ( auto const& x : std::array<std::string, 2> {"x86", "x64"} )
        {
            auto WantedArch = Architecture::Find(x);
            pwn::Assembly::Disassembler d {WantedArch};
            REQUIRE(Failed(d.DisassembleAll(code)));
        }
    }
}
#endif
