#include <pwn.hpp>

#include "./catch.hpp"
#define NS "pwn::utils"

#include <iostream>
#include <vector>


TEST_CASE("hexdump", "[" NS "]")
{
    std::vector<u8> const vec {0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41};
    pwn::utils::hexdump(vec);
    pwn::utils::hexdump(reinterpret_cast<const u8*>("BBCCDDEE"), 8);
}


TEST_CASE("base64", "[" NS "]")
{
    std::vector<u8> const
        vec {0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f};
    std::string const vec_enc = "MDEyMzQ1Njc4OTo7PD0+Pw==";

    SECTION("Base64 encoding test")
    {
        auto encoded_string1 = pwn::utils::Base64::Encode(vec.data(), vec.size());
        auto encoded_string2 = pwn::utils::Base64::Encode(vec);
        REQUIRE(Success(encoded_string1) == true);
        REQUIRE(Success(encoded_string2) == true);
        REQUIRE(Value(encoded_string1) == Value(encoded_string2));
        REQUIRE(Value(encoded_string2) == vec_enc);
    }


    SECTION("Base64 dencoding test")
    {
        auto p = pwn::utils::Base64::Decode(vec_enc);
        REQUIRE(Success(p));
        REQUIRE(Value(p) == vec);

        auto p2 = pwn::utils::Base64::Decode("qweasdzxcpokpo123==");
        REQUIRE(Success(p2) == false);
    }
}


TEST_CASE("cyclic", "[" NS "]")
{
    SECTION("cyclic buffer with period=4")
    {
        std::vector<u8> buf;
        REQUIRE(pwn::utils::cyclic(0x20, 4, buf));
        REQUIRE(buf.size() == 0x20);
        REQUIRE(buf[0] == 'a');
        REQUIRE(buf[4] == 'b');
        REQUIRE(buf[8] == 'c');
    }


    SECTION("cyclic buffer with period determined from architecture")
    {
        std::vector<u8> buf;
        pwn::globals.set("x64");
        REQUIRE(pwn::utils::cyclic(0x30, buf));
        REQUIRE(buf.size() == 0x30);
        pwn::utils::hexdump(buf);
        REQUIRE(buf[0] == 'a');
        REQUIRE(buf[8] == 'b');
        REQUIRE(buf[16] == 'c');
    }
}


TEST_CASE("strings", "[" NS "]")
{
    const char* str0         = "TEST test 1234";
    const std::string str1   = "TEST test 1234";
    const std::wstring wstr0 = L"TEST test 1234";
    const std::wstring wstr1 = L"0000 test 0000";

    REQUIRE(pwn::utils::to_widestring(str0) == wstr0);
    REQUIRE_FALSE(pwn::utils::to_widestring(str0) == wstr1);
    REQUIRE(pwn::utils::to_widestring(str1) == wstr0);
    REQUIRE_FALSE(pwn::utils::to_widestring(str1) == wstr1);
    REQUIRE(pwn::utils::to_string(wstr0) == str1);
    REQUIRE_FALSE(pwn::utils::to_string(wstr1) == str1);
}
