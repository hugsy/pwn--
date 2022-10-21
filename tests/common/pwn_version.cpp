#include "../catch.hpp"

#pragma warning(push)
#pragma warning(disable : 4005) // Disable macro re-definition warnings
#include <pwn.hpp>
#pragma warning(pop)

#define NS "pwn"

TEST_CASE("check version", "[" NS "]")
{
    REQUIRE(pwn::Version != L"");
    auto info = pwn::VersionInfo;
    REQUIRE(std::get<0>(info) >= 0);
    REQUIRE(std::get<1>(info) >= 0);
}
