#include <pwn.hpp>

#include "./catch.hpp"
#define NS "pwn::utils"


TEST_CASE("base64", "[" NS "]")
{
    const std::vector<BYTE> test_buf {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf};
    REQUIRE(pwn::utils::base64_decode(pwn::utils::base64_encode(test_buf.data(), test_buf.size())) == test_buf);
}


TEST_CASE("hexdump", "[" NS "]")
{
    pwn::utils::hexdump(std::vector<BYTE> {0x41, 0x41, 0x41, 0x41, 0x41, 0x41});
    pwn::utils::hexdump(reinterpret_cast<PBYTE>("BBCCDDEE"), 8);
}


TEST_CASE("cyclic", "[" NS "]")
{
    std::vector<u8> buf;

    REQUIRE(pwn::utils::cyclic(0x20, 4, buf));
    REQUIRE(buf.size() == 0x20);
    REQUIRE(buf[0] == 'a');
    REQUIRE(buf[4] == 'b');
    REQUIRE(buf[8] == 'c');

    pwn::context::set_architecture(pwn::context::architecture_t::x64);

    REQUIRE(pwn::utils::cyclic(0x30, buf));
    REQUIRE(buf.size() == 0x30);
    REQUIRE(buf[0] == 'a');
    REQUIRE(buf[8] == 'b');
    REQUIRE(buf[16] == 'c');
}


TEST_CASE("strings", "[" NS "]")
{
    const char* str0        = "TEST test 1234";
    const std::string str1  = "TEST test 1234";
    const std::wstring str2 = L"TEST test 1234";
    const std::wstring str3 = L"0000 test 0000";

    REQUIRE(pwn::utils::to_widestring(str0) == str2);
    REQUIRE_FALSE(pwn::utils::to_widestring(str0) == str3);
    REQUIRE(pwn::utils::string_to_widestring(str1) == str2);
    REQUIRE_FALSE(pwn::utils::string_to_widestring(str1) == str3);
    REQUIRE(pwn::utils::widestring_to_string(str2) == str1);
    REQUIRE_FALSE(pwn::utils::widestring_to_string(str3) == str1);

    REQUIRE(pwn::utils::startswith(str2, L"TEST"));
    REQUIRE_FALSE(pwn::utils::startswith(str2, L"test"));
}