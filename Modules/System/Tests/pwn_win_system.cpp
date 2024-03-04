#include <catch2/catch_test_macros.hpp>

#include "Win32/System.hpp"
#define NS "pwn::System::System"

using namespace pwn;

TEST_CASE("Test basic function", "[" NS "]")
{
    SECTION("check page size")
    {
        CHECK(System::PageSize() == 0x1000);
        CHECK(Success(System::ProcessorCount()));
    }
}

TEST_CASE("System queries", "[" NS "]")
{
    SECTION("SystemBasicInformation")
    {
        auto res = System::Query<SYSTEM_BASIC_INFORMATION>(SystemBasicInformation);
        REQUIRE(Success(res));
        const auto pInfo = Value(res);
        CHECK(pInfo->NumberOfProcessors > 0);
        CHECK(pInfo->PageSize == System::PageSize());
        {
            auto res = System::ProcessorCount();
            REQUIRE(Success(res));
            CHECK(pInfo->NumberOfProcessors == std::get<1>(Value(res)));
        }
    }

#ifdef _WIN64
    SECTION("SystemProcessInformation")
    {
        auto res = System::Query<SYSTEM_PROCESS_INFORMATION>(SystemProcessInformation);
        REQUIRE(Success(res));

        const auto pInfo = Value(res);
        REQUIRE(pInfo->NumberOfThreads > 0);
        CHECK((((uptr)pInfo->Threads[0].StartAddress) & (1ull << 48)) != 0);
    }
#endif

    SECTION("PidOf")
    {
        u32 services_exe_pid = []()
        {
            auto res = System::PidOf(L"services.exe");
            REQUIRE(Success(res));
            auto pids = std::move(Value(res));
            REQUIRE(pids.size() == 1);
            return pids[0];
        }();

        u32 wininit_exe_pid = []()
        {
            auto res = System::PidOf(L"wininit.exe");
            REQUIRE(Success(res));
            auto pids = std::move(Value(res));
            REQUIRE(pids.size() == 1);
            return pids[0];
        }();

        auto res = System::ParentProcessId(services_exe_pid);
        REQUIRE(Success(res));
        u32 services_exe_ppid = Value(res);
        CHECK(services_exe_ppid == wininit_exe_pid);
    }
}
