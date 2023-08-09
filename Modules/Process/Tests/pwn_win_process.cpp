#include <catch.hpp>

#include "Win32/Process.hpp"
#include "Win32/System.hpp"
#include "Win32/Thread.hpp"
#define NS "pwn::Process"

TEST_CASE("Process Local", "[" NS "]")
{
    SECTION("Local process - basic")
    {
        REQUIRE_NOTHROW(Process::Current());

        Process::Process CurrentProcess = Process::Current();
        REQUIRE(CurrentProcess.Handle() != nullptr);
        REQUIRE(CurrentProcess.Handle() != INVALID_HANDLE_VALUE);
        CHECK(CurrentProcess.ProcessId() == ::GetCurrentProcessId());
        CHECK(CurrentProcess.ProcessEnvironmentBlock() == (PPEB)::NtCurrentTeb()->ProcessEnvironmentBlock);
        CHECK(((uptr)CurrentProcess.ProcessEnvironmentBlock() & 0xfff) == 0);
    }

    SECTION("Process threads")
    {
        //
        // Basic Windows thread test - see `pwn_win_thread.cpp` for specific testing
        //
        Process::Process CurrentProcess = Process::Current();

        {
            auto threads = CurrentProcess.Threads();
            REQUIRE(threads.size() > 0);
        }

        {
            auto res       = CurrentProcess.Thread(::GetCurrentThreadId());
            auto CurThread = Value(std::move(res));
            REQUIRE(CurThread.Id() == ::GetCurrentThreadId());
            REQUIRE(CurThread.Handle() != nullptr);
            REQUIRE(CurThread.Handle() != INVALID_HANDLE_VALUE);
            REQUIRE(CurThread.IsRemote() == false);

            auto teb = CurThread.ThreadInformationBlock();
            REQUIRE(teb != nullptr);
            REQUIRE(HandleToULong(teb->ClientId.UniqueProcess) == ::GetCurrentProcessId());
            REQUIRE(HandleToULong(teb->ClientId.UniqueThread) == ::GetCurrentThreadId());
        }
    }

    SECTION("Process queries")
    {
        auto CurrentProcess = Process::Current();
        auto res            = CurrentProcess.Query<PROCESS_BASIC_INFORMATION>(ProcessBasicInformation);
        REQUIRE(Success(res));
        auto const pInfo = Value(std::move(res));
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
            auto res = System::PidOf(TargetProcess);
            REQUIRE(Success(res));
            REQUIRE(Value(res).size() > 0);
            TargetPid = Value(res).at(0);
            INFO("PID Found = " << TargetPid);
            REQUIRE(TargetPid > 0);
        }

        Process::Process Remote(TargetPid);
        REQUIRE(Remote.ProcessId() == TargetPid);
        PPEB RemotePeb = Remote.ProcessEnvironmentBlock();
        CHECK(RemotePeb != nullptr);
        CHECK(((uptr)RemotePeb & 0xfff) == 0);
    }
}


TEST_CASE("Process Memory", "[" NS "]")
{
    SECTION("Local - Enumerate regions")
    {
        auto CurrentProcess = Process::Current();
        REQUIRE(CurrentProcess.IsRemote() == false);

        auto res = Process::Memory(CurrentProcess).Regions();
        REQUIRE(Success(res));

        auto regions = Value(std::move(res));
        CHECK(regions.size() > 0);
    }

    SECTION("Local - Search memory")
    {
        auto CurrentProcess = Process::Current();

        auto CurrentProcessMemory = Process::Memory(CurrentProcess);
        {
            const std::vector<u8> pattern {'M', 'Z'};
            auto res = CurrentProcessMemory.Search(pattern);
            REQUIRE(Success(res));

            auto addrs = Value(std::move(res));
            CHECK(addrs.size() > 0);

            for ( const auto& addr : addrs )
            {
                auto res2 = CurrentProcessMemory.Read(addr, 2);
                CHECK(Success(res2));
                auto val = Value(std::move(res2));
                CHECK(val[0] == 'M');
                CHECK(val[1] == 'Z');
            }
        }
    }

    SECTION("Read/Write remote")
    {
        auto values = Value(System::PidOf(L"explorer.exe"));
        REQUIRE(values.size() > 0);

        Process::Process TargetProcess(values.at(0));
        Process::Memory TargetMemory(TargetProcess);

        auto res = TargetMemory.Allocate(0x1000);
        REQUIRE(Success(res));

        auto mem = Value(res);
        REQUIRE(Success(TargetMemory.Memset(mem, 0x1000, 0x41)));

        auto res2 = TargetMemory.Read(mem, 0x1000);
        REQUIRE(Success(res2));
        auto val2 = Value(std::move(res2));
        for ( auto byte : val2 )
        {
            CHECK(byte == 0x41);
        }
        REQUIRE(Success(TargetMemory.Free(mem)));
    }


    SECTION("Remote - Search memory")
    {
        // TODO
    }
}
