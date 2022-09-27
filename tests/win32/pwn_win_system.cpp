#include <pwn.hpp>

#include "../catch.hpp"
#define NS "pwn::windows::system"

TEST_CASE("Test basic function", "[" NS "]")
{
    SECTION("check page size")
    {
        REQUIRE(pwn::windows::System::PageSize() == 0x1000);
    }
}

TEST_CASE("System queries", "[" NS "]")
{
    auto res = pwn::windows::System::Query<SYSTEM_BASIC_INFORMATION>(SystemBasicInformation);
    REQUIRE(Success(res));
    const auto pInfo = Value(res);
    CHECK(pInfo->NumberOfProcessors > 0);
    CHECK(pInfo->PageSize == pwn::windows::System::PageSize());
}
