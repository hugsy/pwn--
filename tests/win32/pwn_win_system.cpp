#include <pwn.hpp>

#include "../catch.hpp"
#define NS "pwn::windows::system"

TEST_CASE("Test basic function", "[" NS "]")
{
    SECTION("check page size")
    {
        CHECK(pwn::windows::System::PageSize() == 0x1000);
        CHECK(Success(pwn::windows::System::ProcessorCount()));
    }
}

TEST_CASE("System queries", "[" NS "]")
{
    SECTION("SystemBasicInformation")
    {
        auto res = pwn::windows::System::Query<SYSTEM_BASIC_INFORMATION>(SystemBasicInformation);
        REQUIRE(Success(res));
        const auto pInfo = Value(res);
        CHECK(pInfo->NumberOfProcessors > 0);
        CHECK(pInfo->PageSize == pwn::windows::System::PageSize());
        {
            auto res = pwn::windows::System::ProcessorCount();
            REQUIRE(Success(res));
            CHECK(pInfo->NumberOfProcessors == std::get<1>(Value(res)));
        }
    }

#ifdef _WIN64
    SECTION("SystemProcessInformation")
    {
        auto res = pwn::windows::System::Query<SYSTEM_PROCESS_INFORMATION>(SystemProcessInformation);
        REQUIRE(Success(res));

        const auto pInfo = Value(res);
        REQUIRE(pInfo->NumberOfThreads > 0);
        CHECK((((uptr)pInfo->Threads[0].StartAddress) & (1ull << 48)) != 0);
    }
#endif
}
