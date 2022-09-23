#include <pwn.hpp>

#include "../catch.hpp"
#define NS "pwn::windows"

TEST_CASE("Process", "[" NS "]")
{
    SECTION("test1")
    {
        pwn::windows::Process P;
        REQUIRE(P.IsValid());
        // REQUIRE(Value(res).empty());
    }
}
