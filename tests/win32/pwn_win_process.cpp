#include <pwn.hpp>

#include "../catch.hpp"
#define NS "pwn::windows"

TEST_CASE("Process", "[" NS "]")
{
    SECTION("Local tests")
    {
        pwn::windows::Process Local;
        REQUIRE(Local.IsValid());
        REQUIRE(Local.ProcessId() == ::GetCurrentProcessId());
        REQUIRE(Local.ProcessEnvironmentBlock() == (PPEB)::NtCurrentTeb()->ProcessEnvironmentBlock);
    }

    SECTION("Remote tests")
    {
        u32 TargetPid = 0;
        {
            auto res = pwn::windows::system::pidof(L"explorer.exe");
            REQUIRE(Success(res));
            REQUIRE(Value(res).size() > 0);
            TargetPid = Value(res).at(0);
        }

        pwn::windows::Process Remote {TargetPid};
        REQUIRE(Remote.IsValid());
        REQUIRE(Remote.ProcessId() == TargetPid);
        REQUIRE(Remote.ProcessEnvironmentBlock() != nullptr);
    }
}
