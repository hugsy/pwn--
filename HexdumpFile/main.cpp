#include "../pwn++/pwn.h"
#pragma comment(lib, "../x64/release/pwn++.lib")

using namespace pwn::log;

namespace ctx = pwn::context;


auto wmain(_In_ int argc, _In_ const wchar_t** argv)
{
	if (argc < 2)
	{
		err(L"Missing process name\n");
		return EXIT_FAILURE;
	}



	return EXIT_SUCCESS;
}