#include <pwn.hpp>

#include "../catch.hpp"
#define NS "pwn::win::thread"


TEST_CASE("set/get thread names", "[" NS "]")
{
    // get default name, should be non existing
    REQUIRE_FALSE(pwn::win::thread::get_name().has_value());

    // affect a name
    REQUIRE(pwn::win::thread::set_name(L"TestThreadName")); // len=14*2

    // re-test the name
    REQUIRE(pwn::win::thread::get_name().has_value());
    REQUIRE(::RtlCompareMemory((*pwn::win::thread::get_name()).c_str(), L"TestThreadName", 28) == 28);
    REQUIRE((*pwn::win::thread::get_name()).length() == 28);
}