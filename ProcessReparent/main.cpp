#include "../pwn++/pwn.h"
#pragma comment(lib, "../x64/release/pwn++.lib")

using namespace pwn::log;

namespace ctx = pwn::context;


auto wmain(_In_ int argc, _In_ const wchar_t** argv) -> int
{
	if (argc < 2)
	{
		err(L"Missing process name\n");
		return EXIT_FAILURE;
	}

	ctx::set_arch(ctx::arch_t::x64);
	ctx::set_log_level(log_level_t::LOG_DEBUG);

	HANDLE hProcess = INVALID_HANDLE_VALUE;
	auto ppid = pwn::system::pidof(argv[1]);
	info(L"found '%s' pid=%lu\n", argv[1], ppid);
	if (pwn::process::execv(L"cmd.exe", ppid, &hProcess))
	{
		auto h = pwn::generic::GenericHandle(hProcess);
		::WaitForSingleObject(h.Get(), INFINITE);
	}

	return EXIT_SUCCESS;
}