#include <pwn.hpp>

#include "../catch.hpp"
#define NS "pwn::windows::ObjectManager"

TEST_CASE("Object enumeration", "[" NS "]")
{
    SECTION("Existing directories")
    {
        auto res = pwn::windows::ObjectManager::EnumerateDirectory(L"\\");
        REQUIRE(Success(res));
        CHECK(Value(res).size() > 0);
    }
}
