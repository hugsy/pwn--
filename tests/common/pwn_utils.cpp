#include <pwn.hpp>

#include "../catch.hpp"
#define NS "pwn::utils"

#include <iostream>
#include <vector>


TEST_CASE("hexdump", "[" NS "]")
{
    std::vector<u8> vec {0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41};
    pwn::utils::hexdump(vec);
    pwn::utils::hexdump(&vec[0], ((usize)vec.size()));

    pwn::utils::MemoryView view(vec);
    pwn::utils::hexdump(view);
}


TEST_CASE("base64", "[" NS "]")
{
    std::vector<u8> const
        vec {0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f};
    std::string const vec_enc = "MDEyMzQ1Njc4OTo7PD0+Pw==";

    SECTION("Base64 encoding/decoding test")
    {
        auto encoded_string1 = pwn::utils::Base64::Encode(vec.data(), vec.size());
        auto encoded_string2 = pwn::utils::Base64::Encode(vec);
        REQUIRE(Success(encoded_string1));
        REQUIRE(Success(encoded_string2));
        REQUIRE(Value(encoded_string1) == Value(encoded_string2));
        REQUIRE(Value(encoded_string2) == vec_enc);
    }


    SECTION("Base64  test")
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
        auto res = pwn::utils::cyclic(0x20, 4);
        REQUIRE(Success(res));
        std::vector<u8> const& buf = Value(res);
        CHECK(buf.size() == 0x20);
        CHECK(::memcmp((void*)buf.data(), (void*)"aaaabaaacaaadaaaeaaafaaagaaahaaa", 0x20) == 0);
    }

    SECTION("cyclic buffer with period determined from architecture")
    {
        pwn::Context.set("x64");
        auto res = pwn::utils::cyclic(0x30);
        REQUIRE(Success(res));
        std::vector<u8> const& buf = Value(res);
        CHECK(buf.size() == 0x30);
        CHECK(::memcmp((void*)buf.data(), (void*)"aaaaaaaabaaaaaaacaaaaaaadaaaaaaaeaaaaaaafaaaaaaa", 0x30) == 0);
    }
}


TEST_CASE("strings", "[" NS "]")
{
    const std::string str0   = "TEST test 1234";
    const std::string str1   = "0000 test 0000";
    const std::wstring wstr0 = L"TEST test 1234";
    const std::wstring wstr1 = L"0000 test 0000";
    const std::string str    = "TEST test 1234X0000 test 0000";
    const std::wstring wstr  = L"TEST test 1234X0000 test 0000";

    CHECK(pwn::utils::StringLib::To<std::wstring>(str0) == wstr0);
    CHECK(pwn::utils::StringLib::To<std::string>(wstr0) == str0);
    CHECK(pwn::utils::StringLib::To<std::vector<u8>>(wstr0).size() == wstr0.size());

    CHECK(pwn::utils::StringLib::Join(std::vector {str0, str1}, 'X') == str);
    CHECK(pwn::utils::StringLib::Join(std::vector {wstr0, wstr1}, L'X') == wstr);

    CHECK(pwn::utils::StringLib::Split(str, 'X') == std::vector {str0, str1});
    CHECK(pwn::utils::StringLib::Split(wstr, L'X') == std::vector {wstr0, wstr1});

    CHECK(pwn::utils::StringLib::Strip(str1, '0') == " test ");
    CHECK(pwn::utils::StringLib::Strip(wstr1, L'0') == L" test ");
}


TEST_CASE("pack/unpack/flatten", "[" NS "]")
{
    SECTION("LittleEndian")
    {
        pwn::Context.set(Endianess::little);
        CHECK(pwn::utils::Pack::p8(0x41) == std::vector<u8> {0x41});
        CHECK(pwn::utils::Pack::p16(0x4142) == std::vector<u8> {0x42, 0x41});
        CHECK(pwn::utils::Pack::p32(0x41424344) == std::vector<u8> {0x44, 0x43, 0x42, 0x41});
        CHECK(
            pwn::utils::Pack::p64(0x4142434445464748) ==
            std::vector<u8> {0x48, 0x47, 0x46, 0x45, 0x44, 0x43, 0x42, 0x41});

        CHECK(pwn::utils::Pack::Flatten(pwn::utils::Pack::p32(0x41424344)) == std::vector<u8> {0x44, 0x43, 0x42, 0x41});
        CHECK(
            pwn::utils::Pack::Flatten(pwn::utils::Pack::p32(0x41424344), pwn::utils::Pack::p64(0x45464748'494a4b4c)) ==
            std::vector<u8> {0x44, 0x43, 0x42, 0x41, 0x4c, 0x4b, 0x4a, 0x49, 0x48, 0x47, 0x46, 0x45});
    }

    SECTION("BigEndian")
    {
        pwn::Context.set(Endianess::big);
        CHECK(pwn::utils::Pack::p8(0x41) == std::vector<u8> {0x41});
        CHECK(pwn::utils::Pack::p16(0x4142) == std::vector<u8> {0x41, 0x42});
        CHECK(pwn::utils::Pack::p32(0x41424344) == std::vector<u8> {0x41, 0x42, 0x43, 0x44});
        CHECK(
            pwn::utils::Pack::p64(0x4142434445464748) ==
            std::vector<u8> {0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48});

        CHECK(pwn::utils::Pack::Flatten(pwn::utils::Pack::p32(0x41424344)) == std::vector<u8> {0x41, 0x42, 0x43, 0x44});

        CHECK(
            pwn::utils::Pack::Flatten(pwn::utils::Pack::p32(0x41424344), pwn::utils::Pack::p64(0x45464748'494a4b4c)) ==
            std::vector<u8> {0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c});
    }
}


TEST_CASE("security properties", "[" NS "]")
{
}
