#include <catch.hpp>

#include "Win32/PE.hpp"

using namespace pwn;

#define NS "Binary::PE"

TEST_CASE("PE file parser", "[" NS "]")
{
    SECTION("Basic parsing")
    {
        auto res = Binary::PE::Parse(L"c:\\windows\\system32\\kernel32.dll");
        REQUIRE(Success(res));

        const auto pe = Value(res);
        REQUIRE(pe.IsValid());
        REQUIRE(pe.Sections().size() > 1);
        REQUIRE(pe.DataDirectories().size() > 1);
    }
}
