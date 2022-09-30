///
/// @file ProcessReparent
///
/// @author hugsy (hugsy [AT] blah [DOT] cat)
///
/// @brief Simple script using pwn++ to spawn a process reparented
///

#include <pwn.hpp>

auto
wmain(const int argc, const wchar_t** argv) -> int
{
    pwn::Context.set("x64");
    pwn::Context.log_level = pwn::log::LogLevel::Debug;

    const auto target_process = (argc >= 2) ? std::wstring(argv[1]) : std::wstring(L"powershell.exe");
    const auto parent_process = (argc >= 3) ? std::wstring(argv[2]) : std::wstring(L"winlogon.exe");

    // Look for the parent process
    u32 ppid = 0;
    {
        auto res = pwn::windows::System::PidOf(parent_process);
        if ( !Success(res) )
        {
            err(L"failed to find PID of '{}'", parent_process);
            return EXIT_FAILURE;
        }

        ppid = Value(res).front();
        info(L"found winlogon pid={}", ppid);
    }

    // Create the new process using the parent PID
    {
        auto res = pwn::windows::Process::New(target_process, ppid);
        if ( Failed(res) )
        {
            err(L"failed to spawn the process");
            return EXIT_FAILURE;
        }

        auto hProcess = Value(res).handle();
        ::WaitForSingleObject(hProcess, INFINITE);
    }

    return EXIT_SUCCESS;
}
