#include <pwn.hpp>

#include "./catch.hpp"
#define NS "pwn::utils"

#include <vector>
#include <iostream>


TEST_CASE("hexdump", "[" NS "]")
{
    std::vector<u8> const vec{0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41};
    pwn::utils::hexdump(vec);
    pwn::utils::hexdump(reinterpret_cast<u8*>("BBCCDDEE"), 8);
}


TEST_CASE("base64", "[" NS "]")
{
    std::vector<u8> const vec {
        0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
        0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f
    };
    std::string const vec_enc = "MDEyMzQ1Njc4OTo7PD0+Pw==";
    auto encoded_string1 = pwn::utils::base64_encode(vec.data(), vec.size());
    auto encoded_string2 = pwn::utils::base64_encode(vec);
    REQUIRE( encoded_string1 == encoded_string2 );

    // auto const encoded_vector = pwn::utils::string_to_bytes(encoded_string1);
    // pwn::utils::hexdump( encoded_vector );

    // REQUIRE( encoded_string1.size() == vec_enc.size());
    // REQUIRE( encoded_string1 == vec_enc );

    //auto p = pwn::utils::base64_decode( encoded_string1 );
    //REQUIRE( p.has_value());
    //REQUIRE( p.value() == vec);

    //auto p2 = pwn::utils::base64_decode( "qweasdzxcpokpo123==" );
    //REQUIRE_FALSE( p2.has_value());
}

/*
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
*/