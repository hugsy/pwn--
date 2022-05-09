#include <pwn.hpp>

namespace ctx = pwn::context;


auto
wmain(_In_ int argc, _In_ const wchar_t** argv) -> int
{
    pwn::globals.set("x64");
    pwn::globals.log_level = pwn::log::log_level_t::LOG_DEBUG;

    const auto target_process = (argc >= 2) ? std::wstring(argv[1]) : std::wstring(L"cmd.exe");

    auto res = pwn::win::system::pidof(L"winlogon.exe");
    if ( Success(res) )
    {
        auto ppid = Value(res).front();
        info(L"found winlogon pid={}\n", ppid);
        std::optional<HANDLE> hProcess = pwn::win::process::execv(target_process.c_str(), ppid);
        if ( hProcess )
        {
            auto h = pwn::utils::GenericHandle(hProcess.value());
            ::WaitForSingleObject(h.get(), INFINITE);
        }
    }
    return 0;
}
