#include <pwn.h>

using namespace pwn::log;

#define BOOL_AS_STR(x) ((x)==TRUE ? L"TRUE" : L"FALSE")

#define CODE1 "\x55\x48\x8b\x05\xb8\x13\x00\x00"
#define CODE2 "\x90\x48\x31\xc0\xcc\xc3"

#define CODE3 "xor rax, rax; inc rax; nop; ret"


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

	// test disasm
	std::vector<BYTE> insns;
	pwn::disasm::x64((uint8_t*)CODE1, sizeof(CODE1) - 1, insns);
	pwn::disasm::disassemble((uint8_t*)CODE2, sizeof(CODE2) - 1, insns);


	// test asm
	std::vector<BYTE> bytes;
	pwn::assm::x64(CODE3, sizeof(CODE3) - 1, bytes);
	pwn::utils::hexdump(bytes);

	ok(L"Done...\n");
	return 0;
}