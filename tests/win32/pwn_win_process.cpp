#include <pwn.hpp>

#include "../catch.hpp"
#define NS "pwn::windows"

TEST_CASE("Process", "[" NS "]")
{
    pwn::windows::Process P;

    SECTION("test1")
    {
        // auto res = T.Name();
        // REQUIRE(Success(res));
        // REQUIRE(Value(res).empty());
    }
}
