///
/// @file Example using the Process class
///
///

#include <pwn.hpp>

namespace ctx = pwn::context;


auto
wmain(const int argc, const wchar_t** argv) -> int
{
    pwn::globals.set("x64");
    pwn::globals.set(pwn::log::log_level_t::LOG_DEBUG);

    dbg(L"started self");
    {
        auto p = pwn::win::process::Process();
        info(L"pid={}, ppid={}, cmdline='{}' integrity={}", p.pid(), p.ppid(), p.path().c_str(), p.integrity());

        auto res = p.memory().allocate(0x1000);
        if ( Success(res) )
        {
            auto ptr = Value(res);
        }
        else
        {
            err(L"allocate() failed with GLE={:x}", ::GetLastError());
        }
    }
    dbg(L"ended self");


    dbg(L"started notepad");
    {
        auto res = pwn::win::system::pidof(L"Notepad.exe");
        if ( Success(res) )
        {
            auto pids = Value(res);
            if ( pids.size() > 0 )
            {
                auto p = pwn::win::process::Process(pids.front());
                info(L"pid={}, ppid={}, cmdline='{}' integrity={}", p.pid(), p.ppid(), p.path().c_str(), p.integrity());
                info(L"TEB={:#x}, PEB={:#x}", (PVOID)p.teb(), (PVOID)p.peb());
            }
        }
        else
        {
            auto const& e = Error(res);
            err(L"pidof('notepad') failed with GLE={:x}", e.m_errno);
        }
    }
    dbg(L"ended notepad");


    pwn::utils::pause();
    return EXIT_SUCCESS;
}
