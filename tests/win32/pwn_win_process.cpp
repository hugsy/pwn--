#include <pwn.hpp>

#include "../catch.hpp"
#define NS "pwn::windows"

TEST_CASE("Process Local", "[" NS "]")
{
    SECTION("Local process - basic")
    {
        pwn::windows::Process Local;
        REQUIRE(Local.IsValid() == false);

        auto res = pwn::windows::Process::Current();
        REQUIRE(Success(res));
        Local = Value(res);
        REQUIRE(Local.IsValid() == true);
        CHECK(Local.ProcessId() == ::GetCurrentProcessId());
        CHECK(Local.ProcessEnvironmentBlock() == (PPEB)::NtCurrentTeb()->ProcessEnvironmentBlock);
        CHECK(((uptr)Local.ProcessEnvironmentBlock() & 0xfff) == 0);
    }

    SECTION("Process threads")
    {
        auto CurrentProcess = Value(pwn::windows::Process::Current());
        REQUIRE(CurrentProcess.IsValid() == true);

        auto res = CurrentProcess.Threads.List();
        REQUIRE(Success(res));
        auto tids = Value(res);
        REQUIRE(tids.size() > 0);
        CHECK(CurrentProcess.Threads[tids[0]].IsValid());
    }

    SECTION("Process queries")
    {
        auto CurrentProcess = Value(pwn::windows::Process::Current());
        REQUIRE(CurrentProcess.IsValid() == true);

        auto res = CurrentProcess.Query<PROCESS_BASIC_INFORMATION>(ProcessBasicInformation);
        REQUIRE(Success(res));
        auto const pInfo = Value(res);
        CHECK(pInfo->PebBaseAddress == CurrentProcess.ProcessEnvironmentBlock());
        CHECK(pInfo->UniqueProcessId == UlongToHandle(CurrentProcess.ProcessId()));
        CHECK(pInfo->InheritedFromUniqueProcessId == UlongToHandle(CurrentProcess.ParentProcessId()));
    }
}

TEST_CASE("Process Remote", "[" NS "]")
{
    SECTION("Remote process tests")
    {
        const std::wstring TargetProcess {L"explorer.exe"};
        u32 TargetPid = 0;
        {
            auto res = pwn::windows::System::PidOf(TargetProcess);
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
