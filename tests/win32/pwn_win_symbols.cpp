#include <pwn.hpp>

#include "../catch.hpp"
#define NS "pwn::windows::Symbols"

TEST_CASE("Symbols lookup", "[" NS "]")
{
    SECTION("Check modules")
    {
        auto res = pwn::win::Symbols::EnumerateModules();
        REQUIRE(Success(res));

        auto Modules = Value(res);
        REQUIRE(Modules.size() > 0);
    }
}
