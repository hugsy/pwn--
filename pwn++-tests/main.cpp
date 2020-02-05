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
	{
		std::vector<pwn::disasm::insn_t> insns;
		if (pwn::disasm::x64((uint8_t*)CODE1, sizeof(CODE1) - 1, insns))
			for (auto insn : insns)
				ok(L"0x%08x:\t%s\t\t%s\n", insn.address, insn.mnemonic.c_str(), insn.operands.c_str());

		insns.clear();
		if (pwn::disasm::disassemble((uint8_t*)CODE2, sizeof(CODE2) - 1, insns))
			for (auto insn : insns)
				ok(L"0x%08x:\t%s\t\t%s\n", insn.address, insn.mnemonic.c_str(), insn.operands.c_str());
	}

	// test asm
	{
		std::vector<BYTE> bytes;
		pwn::assm::x64(CODE3, sizeof(CODE3) - 1, bytes);
		pwn::utils::hexdump(bytes);
	}

	// test reg
	/// dword
	{
		std::wstring sub_key(L"Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon");
		std::wstring reg_dword(L"FirstLogon");
		DWORD value = -1;
		if(pwn::reg::read_dword(pwn::reg::hkcu(), sub_key, reg_dword, &value) == ERROR_SUCCESS)
			ok(L"FirstLogon=%d\n", value);
	}

	/// string
	{
		std::wstring sub_key(L"SYSTEM\\Software\\Microsoft");
		std::wstring reg_sz(L"BuildLab");
		std::wstring buildLabStr;
		if(pwn::reg::read_wstring(pwn::reg::hklm(), sub_key, reg_sz, buildLabStr)==ERROR_SUCCESS)
			ok(L"BuildLab=%s\n", buildLabStr.c_str());
	}

	/// binary
	{
		std::wstring sub_key(L"SYSTEM\\RNG");
		std::wstring reg_sz(L"Seed");
		std::vector<BYTE> Seed;
		if(pwn::reg::read_binary(pwn::reg::hklm(), sub_key, reg_sz, Seed) == ERROR_SUCCESS)
			pwn::utils::hexdump(Seed);
	}

	// test process
	{
		std::wstring integrity;
		if (pwn::process::get_integrity_level(integrity) == ERROR_SUCCESS)
			ok(L"integrity=%s\n", integrity.c_str());

		pwn::process::execve(L"c:\\windows\\system32\\notepad.exe");
	}

	ok(L"Done...\n");
	return 0;
}