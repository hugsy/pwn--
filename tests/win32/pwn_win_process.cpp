#include <chrono>
#include <pwn.hpp>

#include "../catch.hpp"
#define NS "pwn::windows"

using namespace std::chrono_literals;

TEST_CASE("Process", "[" NS "]")
{
    SECTION("Local tests")
    {
        pwn::windows::Process Local;
        REQUIRE(Local.IsValid() == false);

        auto res = pwn::windows::Process::Current();
        REQUIRE(Success(res));
        Local = Value(res);
        REQUIRE(Local.IsValid() == true);
        CHECK(Local.ProcessId() == ::GetCurrentProcessId());
        CHECK(Local.ProcessEnvironmentBlock() == (PPEB)::NtCurrentTeb()->ProcessEnvironmentBlock);
    }

    SECTION("Remote tests")
    {
        const std::wstring TargetProcess = L"explorer.exe";
        u32 TargetPid                    = 0;
        {
            auto res = pwn::windows::system::pidof(TargetProcess);
            REQUIRE(Success(res));
            REQUIRE(Value(res).size() > 0);
            TargetPid = Value(res).at(0);
            INFO("PID Found = " << TargetPid);
            REQUIRE(TargetPid > 0);
        }

        pwn::windows::Process Remote {TargetPid};
        REQUIRE(Remote.IsValid());
        CHECK(Remote.ProcessId() == TargetPid);
        PPEB RemotePeb = Remote.ProcessEnvironmentBlock();
        CHECK(RemotePeb != nullptr);
        CHECK(((uptr)RemotePeb & 0xfff) == 0);
    }
}
