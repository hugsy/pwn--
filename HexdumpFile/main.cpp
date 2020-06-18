#include "../pwn++/pwn.h"
#pragma comment(lib, "../x64/release/pwn++.lib")

using namespace pwn::log;
namespace ctx = pwn::context;

#include <vector>


auto wmain(_In_ int argc, _In_ const wchar_t** argv) -> int
{
	if (argc < 2)
	{
		err(L"Missing process name\n");
		return EXIT_FAILURE;
	}

	auto h = pwn::generic::GenericHandle(::CreateFile(argv[1], GENERIC_READ, 0, nullptr, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr));
	if (h)
	{
		auto sz = ::GetFileSize(h.Get(), nullptr);
		std::vector<BYTE> bytes(sz);
		DWORD dummy;
		if (::ReadFile(h.Get(), bytes.data(), sz, &dummy, nullptr))
			pwn::utils::hexdump(bytes);
	}

	return EXIT_SUCCESS;
}