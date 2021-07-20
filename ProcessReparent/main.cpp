#include "..\pwn++\pwn.h"

using namespace pwn::log;

namespace ctx = pwn::context;


auto wmain(_In_ int argc, _In_ const wchar_t** argv) -> int
{
	if (argc < 2)
	{
		err(L"Missing process name\n");
		return EXIT_FAILURE;
	}

	ctx::set_architecture(ctx::architecture_t::x64);
	ctx::set_log_level(log_level_t::LOG_DEBUG);

	auto ppid = pwn::system::pidof(L"winlogon.exe");
	info(L"found winlogon pid=%lu\n", ppid);
	std::optional<HANDLE> hProcess = pwn::process::execv(L"cmd.exe", ppid);
	if (hProcess)
	{
		auto h = pwn::utils::GenericHandle(hProcess.value());
		::WaitForSingleObject(h.get(), INFINITE);
	}
	return 0;
}