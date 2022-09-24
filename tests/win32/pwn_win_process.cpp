#include <pwn.hpp>

#include "../catch.hpp"
#define NS "pwn::windows"

TEST_CASE("Process", "[" NS "]")
{
    SECTION("Basic tests")
    {
        pwn::windows::Process Current;
        REQUIRE(Current.IsValid());
        REQUIRE(Current.ProcessId() == ::GetCurrentProcessId());
        REQUIRE(Current.ProcessEnvironmentBlock() == (PPEB)::NtCurrentTeb()->ProcessEnvironmentBlock);
    }
}
