#include <pwn.h>

int wmain(int argc, wchar_t** argv)
{
	pwn::log::ok(L"hi");
	return 0;
}