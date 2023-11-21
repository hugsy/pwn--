#include <catch2/catch_test_macros.hpp>

#include "Pattern.hpp"
#define NS "pwn::Shellcode"

using namespace pwn;

TEST_CASE("Pattern tests", "[" NS "]")
{
    SECTION("PatternFind(no mask)")
    {
        const std::vector<u8> bytes {0x01, 0x02, 0x03, 0x04};
        const std::vector<u8> needle1 {0x01, 0x02};
        const std::vector<u8> needle2 {0x03, 0x04};
        const std::vector<u8> needle3 {0x01, 0x04};

        CHECK(Shellcode::PatternFind(bytes, needle1) == 0);
        CHECK(Shellcode::PatternFind(bytes, needle2) == 2);
        CHECK(Shellcode::PatternFind(bytes, needle3) == -1);
    }

    SECTION("PatternFind(mask)")
    {
        const std::vector<u8> bytes {0x00, 0x11, 0x88, 0xff};
        const std::vector<u8> needle1 {0x00, 0x01};
        const std::vector<u8> mask1 {0x00, 0x0f};
        const std::vector<u8> needle2 {0x80, 0x80};
        const std::vector<u8> mask2 {0xf0, 0x80};
        const std::vector<u8> needle3 {0x88, 0xff};
        const std::vector<u8> mask3 {0x01, 0x00};

        CHECK(Shellcode::PatternFind(bytes, needle1, mask1) == 0);
        CHECK(Shellcode::PatternFind(bytes, needle2, mask2) == 2);
        CHECK(Shellcode::PatternFind(bytes, needle3, mask3) == -1);
    }
}
