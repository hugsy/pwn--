#include <pwn.hpp>

#include "../catch.hpp"
#define NS "pwn::windows::system"


TEST_CASE("check page size", "[" NS "]")
{
    REQUIRE(pwn::windows::system::PageSize() == 0x1000);
}
