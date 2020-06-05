#include <pwn++\pwn.h>

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
	pwn::process::execv(L"cmd.exe", ppid, &hProcess);
	::WaitForSingleObject(hProcess, INFINITE);
	::CloseHandle(hProcess);
	
	return EXIT_SUCCESS;
}