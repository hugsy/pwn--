#include <pwn.h>

using namespace pwn::log;

#define BOOL_AS_STR(x) ((x)==TRUE ? L"TRUE" : L"FALSE")


int wmain(_In_ int argc, _In_ const wchar_t** argv)
{
	HeapSetInformation(NULL, HeapEnableTerminationOnCorruption, NULL, 0);

	// test logging module
	xlog(log_level_t::LOG_OK, L"hello %s\n", L"world");
	ok(L"hello %s\n", L"world");
	::SetLastError(ERROR_ACPI_ERROR);
	perror(std::wstring(L"test perror(ERROR_ACPI_ERROR)"));


	// test system module
	info(L"pagesize=0x%x\n", pwn::system::pagesize());
	info(L"pid=%d\n", pwn::system::pid());
	info(L"ppid=%d\n", pwn::system::ppid());
	info(L"pidof('explorer.exe')=%d\n", pwn::system::pidof(std::wstring(L"explorer.exe")));
	info(L"is_elevated()=%s\n", BOOL_AS_STR(pwn::system::is_elevated()));
	ok(L"Done...\n");
	return 0;
}