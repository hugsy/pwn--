#include <catch.hpp>
#include <pwn.hpp>


#if defined(PWN_INCLUDE_ASSEMBLER)
// TEST_CASE("asm x86-x64", "[pwn::Assembly]")
// {
//     const char* code = "xor rax, rax; inc rax; nop; ret;";

//     std::vector<u8> bytes;
//     std::vector<u8> expected {0x48, 0x31, 0xc0, 0x48, 0xff, 0xc0, 0x90, 0xc3};

//     pwn::context::set_architecture(Architecture::x64);
//     REQUIRE(pwn::assm::assemble(code, sizeof(code) - 1, bytes));
//     REQUIRE(bytes == expected);

//     pwn::context::set_architecture(Architecture::arm64);
//     REQUIRE_FALSE(pwn::assm::assemble(code, sizeof(code) - 1, bytes));
// }
#endif


#if defined(PWN_INCLUDE_DISASSEMBLER)
TEST_CASE("Disassemble", "[pwn::Assembly]")
{

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
