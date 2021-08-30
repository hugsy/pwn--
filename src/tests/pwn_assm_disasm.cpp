#include <pwn.hpp>

#include "./catch.hpp"


#ifndef PWN_NO_ASSEMBLER
TEST_CASE("asm x86-x64", "[pwn::assm]")
{
    const char* code = "xor rax, rax; inc rax; nop; ret;";

    std::vector<u8> bytes;
    std::vector<u8> expected {0x48, 0x31, 0xc0, 0x48, 0xff, 0xc0, 0x90, 0xc3};

    pwn::context::set_architecture(pwn::context::architecture_t::x64);
    REQUIRE(pwn::assm::assemble(code, sizeof(code) - 1, bytes));
    REQUIRE(bytes == expected);

    pwn::context::set_architecture(pwn::context::architecture_t::arm64);
    REQUIRE_FALSE(pwn::assm::assemble(code, sizeof(code) - 1, bytes));
}
#endif


#ifndef PWN_NO_DISASSEMBLER
TEST_CASE("disasm x86-x64", "[pwn::disasm]")
{
	std::vector<pwn::disasm::insn_t> insns;
	const u8 code1[] = {0x90, 0x48, 0x31, 0xc0, 0xcc, 0xc3};
	// x64 - nop; xor rax, rax; int3; ret
	// x86 - nop; dec eax; xor eax, eax; int3; ret

	pwn::context::set_architecture(pwn::context::architecture_t::x64);
	REQUIRE(pwn::disasm::disassemble(code1, sizeof(code1), insns));
	REQUIRE(insns.size() == (size_t)4);

	insns.clear();

	pwn::context::set_architecture(pwn::context::architecture_t::x86);
	REQUIRE(pwn::disasm::disassemble(code1, sizeof(code1), insns));
	REQUIRE(insns.size() == (size_t)5);

	insns.clear();
	const uint8_t code3[] = {0xff, 0xff};
	REQUIRE_FALSE(pwn::disasm::disassemble(code3, sizeof(code3), insns));
}
#endif
