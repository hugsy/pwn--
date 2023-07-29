#include <catch.hpp>

#include "Linux/System.hpp"
#define NS "pwn::System::System"

using namespace pwn;


TEST_CASE("System tests", "[" NS "]")
{
    SECTION("Page size")
    {
        REQUIRE(pwn::linux::system::pagesize() == 0x1000);
    }
}
