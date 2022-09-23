#include <pwn.hpp>

#include "../catch.hpp"
#define NS "pwn::windows::thread"


TEST_CASE("set/get thread names", "[" NS "]")
{
    std::wstring const expected_name = L"TestThreadName";
    pwn::windows::Thread T;

    SECTION("Get the initial name of thread (expecting none)")
    {
        auto res = T.Name();
        REQUIRE(Success(res));
        REQUIRE(Value(res).empty());
    }

    SECTION("Set a name of thread and check it")
    {
        {
            auto res = T.Name(expected_name);
            REQUIRE(Success(res));
            REQUIRE(Value(res) == true);
        }
        {
            auto res = T.Name();
            REQUIRE(Success(res));

            auto const thread_name = Value(res);
            REQUIRE_FALSE(thread_name.empty());
            REQUIRE(thread_name == expected_name);
            REQUIRE(thread_name.length() == expected_name.length());
        }
    }
}
