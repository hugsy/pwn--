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

    dbg(L"started test");
    {
        auto p = pwn::win::process::Process();
        info(L"pid={}, ppid={}, cmdline='{}' integrity={}", p.pid(), p.ppid(), p.path().c_str(), (int)p.integrity());

        auto ptr = p.allocate(0x1000);
    }
    dbg(L"ended test");

    pwn::utils::pause();
    return EXIT_SUCCESS;
}
