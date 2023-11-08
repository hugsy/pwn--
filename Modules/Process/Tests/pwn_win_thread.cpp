#include <catch2/catch_test_macros.hpp>

#include "Win32/Thread.hpp"

#define NS "pwn::Process::Thread"

constexpr std::wstring_view TestThreadName = L"TestThreadName";

TEST_CASE("set/get thread names", "[" NS "]")
{
    SECTION("Get the current thread")
    {
        auto CurrentThread = Process::Thread::Current();
        REQUIRE(CurrentThread.ThreadId() == ::GetCurrentThreadId());
        REQUIRE(CurrentThread.IsRemote() == false);
    }

    SECTION("Get the initial name of thread (expecting none)")
    {
        auto CurrentThread = Process::Thread::Current();
        auto res           = CurrentThread.Name();
        REQUIRE(Success(res));
        CHECK(Value(res).empty());
    }

    SECTION("Set a name of thread and check it")
    {
        auto CurrentThread = Process::Thread::Current();

        auto res3 = CurrentThread.Name(TestThreadName);
        REQUIRE(Success(res3));
        CHECK(Value(res3) == true);
        auto res2 = CurrentThread.Name();
        REQUIRE(Success(res3));
        auto const thread_name = Value(res2);
        CHECK(!thread_name.empty());
        CHECK(thread_name == TestThreadName);
        CHECK(thread_name.length() == TestThreadName.length());
    }

    SECTION("Test queries")
    {
        auto CurrentThread = Process::Thread::Current();
        auto res           = CurrentThread.Query<THREAD_BASIC_INFORMATION>(THREADINFOCLASS::ThreadBasicInformation);
        REQUIRE(Success(res));
        const auto pInfo = Value(std::move(res));
        CHECK(pInfo->ClientId.UniqueProcess == ULongToHandle(::GetCurrentProcessId()));
        CHECK(pInfo->ClientId.UniqueThread == ULongToHandle(::GetCurrentThreadId()));
    }
}
