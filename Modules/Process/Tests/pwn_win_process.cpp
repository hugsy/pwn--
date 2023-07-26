#include <catch.hpp>

#include "Win32/Process.hpp"
#include "Win32/System.hpp"
#include "Win32/Thread.hpp"
#define NS "pwn::Process"

TEST_CASE("Process Local", "[" NS "]")
{
    // SECTION("Local process - basic")
    // {
    //     auto res = Process::Process::Current();
    //     REQUIRE(Success(res));

    //     Process::Process Local = Value(res);
    //     REQUIRE(Local.IsValid() == true);
    //     REQUIRE(Local.Handle() != nullptr);
    //     CHECK(Local.ProcessId() == ::GetCurrentProcessId());
    //     CHECK(Local.ProcessEnvironmentBlock() == (PPEB)::NtCurrentTeb()->ProcessEnvironmentBlock);
    //     CHECK(((uptr)Local.ProcessEnvironmentBlock() & 0xfff) == 0);
    // }

    // SECTION("Process threads")
    // {
    //     auto CurrentProcess = Value(Process::Process::Current());
    //     REQUIRE(CurrentProcess.IsValid() == true);

    //     auto res = CurrentProcess.Threads();
    //     REQUIRE(res.size() > 0);

    //     auto res2 = CurrentProcess.Thread(::GetCurrentThreadId());
    //     REQUIRE(Success(res2));
    //     const auto CurThread = Value(std::move(res2));
    //     REQUIRE(CurThread.IsValid());
    // }

    // SECTION("Process queries")
    // {
    //     auto CurrentProcess = Value(Process::Process::Current());
    //     REQUIRE(CurrentProcess.IsValid() == true);

    //     auto res = CurrentProcess.Query<PROCESS_BASIC_INFORMATION>(ProcessBasicInformation);
    //     REQUIRE(Success(res));
    //     auto const pInfo = Value(res);
    //     CHECK(pInfo->PebBaseAddress == CurrentProcess.ProcessEnvironmentBlock());
    //     CHECK(pInfo->UniqueProcessId == UlongToHandle(CurrentProcess.ProcessId()));
    //     CHECK(pInfo->InheritedFromUniqueProcessId == UlongToHandle(CurrentProcess.ParentProcessId()));
    // }
}


// TEST_CASE("Process Remote", "[" NS "]")
// {
//     SECTION("Remote process tests")
//     {
//         const std::wstring TargetProcess {L"explorer.exe"};
//         u32 TargetPid = 0;
//         {
//             auto res = System::PidOf(TargetProcess);
//             REQUIRE(Success(res));
//             REQUIRE(Value(res).size() > 0);
//             TargetPid = Value(res).at(0);
//             INFO("PID Found = " << TargetPid);
//             REQUIRE(TargetPid > 0);
//         }

//         Process::Process Remote {TargetPid};
//         REQUIRE(Remote.IsValid());
//         CHECK(Remote.ProcessId() == TargetPid);
//         PPEB RemotePeb = Remote.ProcessEnvironmentBlock();
//         CHECK(RemotePeb != nullptr);
//         CHECK(((uptr)RemotePeb & 0xfff) == 0);
//     }
// }


// TEST_CASE("Process Memory", "[" NS "]")
// {
//     SECTION("Read/Write")
//     {
//     }

//     SECTION("Local - Enumerate regions")
//     {
//         Process::Process CurrentProcess = []()
//         {
//             auto res = Process::Process::Current();
//             REQUIRE(Success(res));
//             return Value(res);
//         }();

//         REQUIRE(CurrentProcess.IsValid() == true);
//         REQUIRE(CurrentProcess.IsRemote() == false);


//         {
//             auto res = Process::Memory(CurrentProcess).Regions();
//             REQUIRE(Success(res));

//             auto regions = Value(res);
//             CHECK(regions.size() > 0);
//         }
//     }

//     SECTION("Local - Search memory")
//     {
//         Process::Process CurrentProcess = []()
//         {
//             auto res = Process::Process::Current();
//             REQUIRE(Success(res));
//             return Value(res);
//         }();

//         auto CurrentProcessMemory = Process::Memory(CurrentProcess);
//         {
//             std::vector<u8> pattern {'M', 'Z'};
//             auto res = CurrentProcessMemory.Search(pattern);
//             REQUIRE(Success(res));

//             auto addrs = Value(res);
//             CHECK(addrs.size() > 0);
//             for ( const auto& addr : addrs )
//             {
//                 auto res2 = CurrentProcessMemory.Read(addr, 2);
//                 CHECK(Success(res2));
//                 auto val = Value(res2);
//                 CHECK(val[0] == 'M');
//                 CHECK(val[1] == 'Z');
//             }
//         }
//     }

//     SECTION("Remote - Search memory")
//     {
//     }
// }


// TEST_CASE("Process Hooking", "[" NS "]")
// {
//     SECTION("Local")
//     {
//         auto res = Process::Process::Current();
//         REQUIRE(Success(res));
//         Process::Process CurrentProcess = Value(std::move(res));

//         REQUIRE(CurrentProcess.IsValid() == true);
//         REQUIRE(CurrentProcess.IsRemote() == false);

//         const uptr TargetFunction = (uptr)::GetProcAddress(::LoadLibraryA("kernel32.dll"),
//         "GetCurrentProcessorNumber"); REQUIRE(TargetFunction != 0);

//         INFO("Found TargetFunction at " << std::hex << TargetFunction);
//     }

//     SECTION("Remote")
//     {
//     }
// }
