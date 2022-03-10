#include <pwn.hpp>

#include "../catch.hpp"
#define NS "pwn::win::thread"


TEST_CASE("set/get thread names", "[" NS "]")
{
    std::wstring const expected_name = L"TestThreadName";

    SECTION("Get the initial name of thread (expecting none)")
    {
        auto const thread_name = pwn::win::thread::get_name();
        REQUIRE_FALSE(thread_name.has_value());
    }

    SECTION("Set a name of thread and check it")
    {
        REQUIRE(pwn::win::thread::set_name(expected_name));
        auto const thread_name = pwn::win::thread::get_name();
        REQUIRE(thread_name.has_value());
        REQUIRE(thread_name.value() == expected_name);
        REQUIRE(thread_name.value().length() == expected_name.length());
    }
}
