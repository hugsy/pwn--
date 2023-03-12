#include <catch.hpp>

#include "Win32/System.hpp"
#define NS "pwn::System::System"

using namespace pwn;

TEST_CASE("Test basic function", "[" NS "]")
{
    SECTION("check page size")
    {
        CHECK(System::System::PageSize() == 0x1000);
        CHECK(Success(System::System::ProcessorCount()));
    }
}

TEST_CASE("System queries", "[" NS "]")
{
    SECTION("SystemBasicInformation")
    {
        auto res = System::System::Query<SYSTEM_BASIC_INFORMATION>(SystemBasicInformation);
        REQUIRE(Success(res));
        const auto pInfo = Value(res);
        CHECK(pInfo->NumberOfProcessors > 0);
        CHECK(pInfo->PageSize == System::System::PageSize());
        {
            auto res = System::System::ProcessorCount();
            REQUIRE(Success(res));
            CHECK(pInfo->NumberOfProcessors == std::get<1>(Value(res)));
        }
    }

#ifdef _WIN64
    SECTION("SystemProcessInformation")
    {
        auto res = System::System::Query<SYSTEM_PROCESS_INFORMATION>(SystemProcessInformation);
        REQUIRE(Success(res));

        const auto pInfo = Value(res);
        REQUIRE(pInfo->NumberOfThreads > 0);
        CHECK((((uptr)pInfo->Threads[0].StartAddress) & (1ull << 48)) != 0);
    }
#endif
}
