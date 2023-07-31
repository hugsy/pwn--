#include <catch.hpp>

#include "Linux/System.hpp"
#define NS "pwn::Linux::System"

using namespace pwn;


TEST_CASE("System tests", "[" NS "]")
{
    SECTION("Page size")
    {
        REQUIRE(pwn::Linux::System::PageSize() == 0x1000);
    }
}
