#include <catch2/catch_test_macros.hpp>

#include "Win32/ObjectManager.hpp"
#define NS "pwn::System::ObjectManager"

using namespace pwn;

TEST_CASE("Object enumeration", "[" NS "]")
{
    SECTION("Existing directories")
    {
        auto res = System::ObjectManager::EnumerateDirectory(L"\\");
        REQUIRE(Success(res));
        CHECK(Value(res).size() > 0);
    }
}
