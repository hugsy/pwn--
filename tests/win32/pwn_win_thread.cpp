#include <pwn.hpp>

#include "../catch.hpp"
#define NS "pwn::windows::thread"


TEST_CASE("set/get thread names", "[" NS "]")
{
    SECTION("Get the current thread")
    {
        pwn::windows::Thread CurrentThread;
        auto res = pwn::windows::Thread::Current();
        REQUIRE(Success(res));
        CurrentThread = Value(res);
        REQUIRE(CurrentThread.IsValid());
        REQUIRE(CurrentThread.ThreadId() == ::GetCurrentThreadId());
    }

    SECTION("Get the initial name of thread (expecting none)")
    {
        auto CurrentThread = Value(pwn::windows::Thread::Current());
        REQUIRE(CurrentThread.IsValid());

        auto res = CurrentThread.Name();
        REQUIRE(Success(res));
        CHECK(Value(res).empty());
    }

    SECTION("Set a name of thread and check it")
    {
        std::wstring const expected_name = L"TestThreadName";
        auto CurrentThread               = Value(pwn::windows::Thread::Current());
        REQUIRE(CurrentThread.IsValid());

        auto res = CurrentThread.Name(expected_name);
        REQUIRE(Success(res));
        CHECK(Value(res) == true);
        auto res2 = CurrentThread.Name();
        REQUIRE(Success(res));
        auto const thread_name = Value(res2);
        CHECK(!thread_name.empty());
        CHECK(thread_name == expected_name);
        CHECK(thread_name.length() == expected_name.length());
    }

    SECTION("Test queries")
    {
        std::wstring const expected_name = L"TestThreadName";
        auto CurrentThread               = Value(pwn::windows::Thread::Current());
        REQUIRE(CurrentThread.IsValid());

        auto res = CurrentThread.Query<THREAD_BASIC_INFORMATION>(ThreadBasicInformation);
        REQUIRE(Success(res));
        const auto pInfo = Value(res);
        CHECK(pInfo->ClientId.UniqueProcess == ULongToHandle(::GetCurrentProcessId()));
        CHECK(pInfo->ClientId.UniqueThread == ULongToHandle(::GetCurrentThreadId()));
    }
}
