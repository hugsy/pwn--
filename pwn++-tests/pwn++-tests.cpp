#include "pch.h"
#include "CppUnitTest.h"

using namespace Microsoft::VisualStudio::CppUnitTestFramework;

#include "..\pwn++\pwn.h"

using namespace pwn::log;

#define BOOL_AS_STR(x) ((x)==TRUE ? L"TRUE" : L"FALSE")

#define CODE1 "\x9c\xc3" // x86
#define CODE2 "\x90\x48\x31\xc0\xcc\xc3" // x64
#define CODE3 "xor rax, rax; inc rax; nop; ret"


static inline void pause()
{
#pragma warning(disable: 6031)
	ok(L"press enter to continue...");
	::getchar();
#pragma warning(default: 6031)
}



namespace pwn::tests
{
	TEST_CLASS(UnitPwnGeneric)
	{
	public:

		TEST_METHOD(Test_version_info)
		{
			auto version = pwn::version_info();
			Assert::IsTrue(std::get<0>(version) == __PWNLIB_VERSION_MAJOR__);
			Assert::IsTrue(std::get<1>(version) == __PWNLIB_VERSION_MINOR__);
			ok(L"running pwn++ v%d.%02d\n", std::get<0>(version), std::get<1>(version));
		}
	};


	TEST_CLASS(UnitPwnUtils)
	{
	public:
		TEST_METHOD(Test_perror)
		{
			::SetLastError(ERROR_ACPI_ERROR);
			perror(std::wstring(L"test perror(ERROR_ACPI_ERROR)"));
			::SetLastError(ERROR_SUCCESS);
		}

		TEST_METHOD(Test_hexdump)
		{
			pwn::utils::hexdump(std::vector<BYTE>{ 0x41, 0x41, 0x41, 0x41, 0x41, 0x41 });
			pwn::utils::hexdump( reinterpret_cast<PBYTE>("BBCCDDEE"), 8);
		}

		TEST_METHOD(Test_cyclic)
		{
			std::vector<BYTE> buf;

			Assert::IsTrue(pwn::utils::cyclic(0x20, 4, buf));
			Assert::IsTrue(buf.size() == 0x20);
			Assert::IsTrue(buf[0] == 'a');
			Assert::IsTrue(buf[4] == 'b');
			Assert::IsTrue(buf[8] == 'c');

			pwn::context::set_architecture(pwn::context::architecture_t::x64);

			Assert::IsTrue(pwn::utils::cyclic(0x30, buf));
			Assert::IsTrue(buf.size() == 0x30);
			Assert::IsTrue(buf[0] == 'a');
			Assert::IsTrue(buf[8] == 'b');
			Assert::IsTrue(buf[16] == 'c');
		}

		TEST_METHOD(Test_string)
		{
			const char* str0 = "TEST test 1234";
			const std::string str1 = "TEST test 1234";
			const std::wstring str2 = L"TEST test 1234";
			const std::wstring str3 = L"0000 test 0000";
			
			Assert::IsTrue(pwn::utils::to_widestring(str0) == str2);
			Assert::IsFalse(pwn::utils::to_widestring(str0) == str3);
			Assert::IsTrue(pwn::utils::string_to_widestring(str1) == str2);
			Assert::IsFalse(pwn::utils::string_to_widestring(str1) == str3);
			Assert::IsTrue(pwn::utils::widestring_to_string(str2) == str1);
			Assert::IsFalse(pwn::utils::widestring_to_string(str3) == str1);

			Assert::IsTrue(pwn::utils::startswith(str2, L"TEST"));
			Assert::IsFalse(pwn::utils::startswith(str2, L"test"));
		}

		TEST_METHOD(Test_base64)
		{
			const std::vector<BYTE> test_buf { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf };
			Assert::IsTrue(pwn::utils::base64_decode(pwn::utils::base64_encode(test_buf.data(), test_buf.size())) == test_buf );
		}
	};


	TEST_CLASS(UnitPwnAsm)
	{
	public:
		TEST_METHOD(Test_assemble)
		{
			const char* code = "xor rax, rax; inc rax; nop; ret;";

			std::vector<BYTE> bytes;
			std::vector<BYTE> expected{ 0x48, 0x31, 0xc0, 0x48, 0xff, 0xc0, 0x90, 0xc3 };

			pwn::context::set_architecture(pwn::context::architecture_t::x64);
			Assert::IsTrue( pwn::assm::assemble(code, sizeof(code) - 1, bytes));
			Assert::IsTrue( bytes == expected);
			
			pwn::context::set_architecture(pwn::context::architecture_t::arm64);
			Assert::IsFalse( pwn::assm::assemble(code, sizeof(code) - 1, bytes) );
		}
	};


	TEST_CLASS(UnitPwnDisasm)
	{
	public:
		TEST_METHOD(Test_disassemble)
		{
			std::vector<pwn::disasm::insn_t> insns;
			const uint8_t code1[] = { 0x90, 0x48, 0x31, 0xc0, 0xcc, 0xc3 };  
				// x64 - nop; xor rax, rax; int3; ret
				// x86 - nop; dec eax; xor eax, eax; int3; ret

			pwn::context::set_architecture(pwn::context::architecture_t::x64);
			Assert::IsTrue(pwn::disasm::disassemble(code1, sizeof(code1), insns));
			insns.size();
			Assert::IsTrue(insns.size() == 4);

			insns.clear();

			pwn::context::set_architecture(pwn::context::architecture_t::x86);
			Assert::IsTrue(pwn::disasm::disassemble(code1, sizeof(code1), insns));
			Assert::IsTrue(insns.size() == 5);

			insns.clear();
			const uint8_t code3[] = { 0xff, 0xff };
			Assert::IsFalse(pwn::disasm::disassemble(code3, sizeof(code3), insns));
		}
	};



	TEST_CLASS(UnitPwnCrypto)
	{
	public:
		TEST_METHOD(Test_crc)
		{
			std::vector<BYTE> data { 0x41, 0x42, 0x43, 0x44 };
			Assert::IsTrue(pwn::crypto::crc8(data) == 0xd7);
			Assert::IsTrue(pwn::crypto::crc16(data) == 0xf9bd);
			Assert::IsTrue(pwn::crypto::crc32(data) == 0x80e38938);
			Assert::IsTrue(pwn::crypto::crc64(data) == 0xbda275f960e7cf9a);
		}

		TEST_METHOD(Test_md)
		{
			std::vector<BYTE> data{ 0x41, 0x42, 0x43, 0x44 };
			std::array<BYTE, MD5LEN> expected1{ 0xcb, 0x08, 0xca, 0x4a, 0x7b, 0xb5, 0xf9, 0x68, 0x3c, 0x19, 0x13, 0x3a, 0x84, 0x87, 0x2c, 0xa7};
			std::array<BYTE, MD5LEN> expected2{ 0x71, 0x1e, 0xe0, 0x36, 0x48, 0xa6, 0x9e, 0x29, 0x6e, 0xcc, 0x7b, 0x77, 0x07, 0xed, 0x33, 0xeb};
			std::array<BYTE, MD5LEN> expected3{ 0x3f, 0x2c, 0x0a, 0xa4, 0xc0, 0x76, 0x11, 0x84, 0x6e, 0xa3, 0x3f, 0x44, 0xa8, 0xcc, 0x9e, 0x32};
			Assert::IsTrue(pwn::crypto::md5(data) == expected1);
			Assert::IsTrue(pwn::crypto::md2(data) == expected2);
			Assert::IsTrue(pwn::crypto::md4(data) == expected3);
		}

		TEST_METHOD(Test_sha)
		{
			std::vector<BYTE> data{ 0x41, 0x42, 0x43, 0x44 };
			std::array<BYTE, SHA1LEN> expected1{ 0xfb,0x2f,0x85,0xc8,0x85,0x67,0xf3,0xc8,0xce,0x9b,0x79,0x9c,0x7c,0x54,0x64,0x2d,0xc,0x7b,0x41,0xf6 };
			Assert::IsTrue(pwn::crypto::sha1(data) == expected1);
			std::array<BYTE, SHA256LEN> expected2{ 0xe1,0x2e,0x11,0x5a,0xcf,0x45,0x52,0xb2,0x56,0x8b,0x55,0xe9,0x3c,0xbd,0x39,0x39,0x4c,0x4e,0xf8,0x1c,0x82,0x44,0x7f,0xaf,0xc9,0x97,0x88,0x2a,0x2,0xd2,0x36,0x77 };
			Assert::IsTrue(pwn::crypto::sha256(data) == expected2);
			std::array<BYTE, SHA512LEN> expected3{ 0x49, 0xec, 0x55, 0xbd, 0x83, 0xfc, 0xd6, 0x78, 0x38, 0xe3, 0xd3, 0x85, 0xce, 0x83, 0x16, 0x69, 0xe3, 0xf8, 0x15, 0xa7, 0xf4, 0x4b, 0x7a, 0xa5, 0xf8, 0xd5, 0x2b, 0x5d, 0x42, 0x35, 0x4c, 0x46, 0xd8, 0x9c, 0x8b, 0x9d, 0x6, 0xe4, 0x7a, 0x79, 0x7a, 0xe4, 0xfb, 0xd2, 0x22, 0x91, 0xbe, 0x15, 0xbc, 0xc3, 0x5b, 0x7, 0x73, 0x5c, 0x4a, 0x6f, 0x92, 0x35, 0x7f, 0x93, 0xd5, 0xa3, 0x3d, 0x9b};
			Assert::IsTrue(pwn::crypto::sha512(data) == expected3);
		}
	};


}
