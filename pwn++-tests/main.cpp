#include <pwn.h>

using namespace pwn::log;


#define BOOL_AS_STR(x) ((x)==TRUE ? L"TRUE" : L"FALSE")

#define CODE1 "\x9c\xc3" // x86
#define CODE2 "\x90\x48\x31\xc0\xcc\xc3" // x64
#define CODE3 "xor rax, rax; inc rax; nop; ret"


int wmain(_In_ int argc, _In_ const wchar_t** argv)
{
	HeapSetInformation(NULL, HeapEnableTerminationOnCorruption, NULL, 0);

	if ( 0 )
	{
		auto version = pwn::version_info();
		ok(L"running pwn++ v%d.%02d\n", std::get<0>(version), std::get<1>(version));
	}

	// change the context architecture to x64
	pwn::context::set_arch(pwn::context::arch_t::x64);


	// make context at debug level for max verbosity
	pwn::context::set_log_level(pwn::log::log_level_t::LOG_DEBUG);


	// test logging & utils module
	if ( 0 )
	{
		::SetLastError(ERROR_ACPI_ERROR);
		perror(std::wstring(L"test perror(ERROR_ACPI_ERROR)"));
		::SetLastError(ERROR_SUCCESS);

		std::vector<BYTE> buf;
		if ( pwn::utils::cyclic(0x20, 4, buf) )
		{
			pwn::utils::hexdump(buf);
		}

		if ( pwn::utils::cyclic(0x30, buf) )
		{
			pwn::utils::hexdump(buf);
		}
	}

	// test system module
	if ( 0 )
	{
		info(L"computer_name=%s\n", pwn::system::name().c_str());
		info(L"pagesize=0x%x\n", pwn::system::pagesize());
		info(L"pid=%d\n", pwn::system::pid());
		info(L"ppid=%d\n", pwn::system::ppid());
		info(L"pidof('explorer.exe')=%d\n", pwn::system::pidof(std::wstring(L"explorer.exe")));
		info(L"is_elevated()=%s\n", BOOL_AS_STR(pwn::system::is_elevated()));
		info(L"peb()=%p\n", pwn::process::peb());
		info(L"teb()=%p\n", pwn::process::teb());
	}

	// test disasm
	if ( 0 )
	{
		std::vector<pwn::disasm::insn_t> insns;
		if ( pwn::disasm::x86((uint8_t*)CODE1, sizeof(CODE1) - 1, insns) )
			for ( auto insn : insns )
				ok(L"0x%08x:\t%s\t\t%s\n", insn.address, insn.mnemonic.c_str(), insn.operands.c_str());

		insns.clear();
		if ( pwn::disasm::disassemble((uint8_t*)CODE2, sizeof(CODE2) - 1, insns) )
			for ( auto insn : insns )
				ok(L"0x%08x:\t%s\t\t%s\n", insn.address, insn.mnemonic.c_str(), insn.operands.c_str());
	}


	// test asm
	if ( 0 )
	{
		std::vector<BYTE> bytes;
		pwn::assm::x64(CODE3, sizeof(CODE3) - 1, bytes);
		pwn::utils::hexdump(bytes);
	}


	// test reg
	/// dword
	if ( 0 )
	{
		std::wstring sub_key(L"Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon");
		std::wstring reg_dword(L"FirstLogon");
		DWORD value = -1;
		if ( pwn::reg::read_dword(pwn::reg::hkcu(), sub_key, reg_dword, &value) == ERROR_SUCCESS )
			ok(L"FirstLogon=%d\n", value);
	}

	/// string
	if ( 0 )
	{
		std::wstring sub_key(L"SYSTEM\\Software\\Microsoft");
		std::wstring reg_sz(L"BuildLab");
		std::wstring BuildLab;
		if ( pwn::reg::read_wstring(pwn::reg::hklm(), sub_key, reg_sz, BuildLab) == ERROR_SUCCESS )
			ok(L"BuildLab=%s\n", BuildLab.c_str());
	}

	/// binary
	if ( 0 )
	{
		std::wstring sub_key(L"SYSTEM\\RNG");
		std::wstring reg_sz(L"Seed");
		std::vector<BYTE> Seed;
		if ( pwn::reg::read_binary(pwn::reg::hklm(), sub_key, reg_sz, Seed) == ERROR_SUCCESS )
			pwn::utils::hexdump(Seed);
	}

	// test process
	if ( 0 )
	{
		/// integrity
		std::wstring integrity;
		if ( pwn::process::get_integrity_level(integrity) == ERROR_SUCCESS )
			ok(L"integrity=%s\n", integrity.c_str());
		else
			perror(L"pwn::process::get_integrity_level()");

		/// spawn new process
		HANDLE hProcess;
		if ( pwn::process::execv(L"c:\\windows\\system32\\notepad.exe hello.txt", &hProcess) )
			pwn::process::kill(hProcess);

		/// mem write & read
		auto peb_loc = pwn::process::peb();
		auto peb_cnt = pwn::process::mem::read(peb_loc, 0x10);
		pwn::utils::hexdump(peb_cnt);
		std::vector<BYTE> new_peb = { 0x13, 0x37, 0x13, 0x37 };
		pwn::process::mem::write(peb_loc, new_peb);
		peb_cnt = pwn::process::mem::read(peb_loc, 0x10);
		pwn::utils::hexdump(peb_cnt);
	}


	// test cpu
	if ( 0 )
	{
		DWORD nb_cores = pwn::cpu::nb_cores();
		ok(L"nb_cores=%ld\n", nb_cores);
	}


	// test job
	if ( 0 )
	{
		/// create a process and add it to an anonymous job
		HANDLE hProcess;
		auto ppid = pwn::system::ppid();
		pwn::process::execv(L"notepad.exe", ppid, &hProcess);
		auto hJob = pwn::job::create();
		auto pid = pwn::system::pid(hProcess);
		pwn::job::add_process(hJob, pid);
		::WaitForSingleObject(hProcess, INFINITE);
		pwn::job::close(hJob);
	}

	if ( 0 )
	{
		DWORD i = 10;
		for ( auto p : pwn::process::list() )
		{
			std::wstring integrity;
			pwn::process::get_integrity_level(p.pid, integrity);
			ok(L"%d -> %s (i=%s)\n", p.pid, p.name.c_str(), integrity.c_str());
			if ( !--i ) break;
		}

		auto p = pwn::process::mem::alloc(0x100, L"rwx");
		ok(L"allocated(rwx) at %p\n", p);
		pwn::process::mem::free(p);
		p = pwn::process::mem::alloc(0x100, L"rx");
		ok(L"allocated(rx) at %p\n", p);
		pwn::process::mem::free(p);
		p = pwn::process::mem::alloc(0x100, L"rw");
		ok(L"allocated(rw) at %p\n", p);
		pwn::process::mem::free(p);
	}


	// test kernel::shellcode
	if ( 0 )
	{
		auto out = pwn::kernel::shellcode::steal_system_token();
		ok(L"compiled sc:\n");
		pwn::utils::hexdump(out);

		auto mem = pwn::process::mem::alloc(0x1000, L"rwx");
		ok(L"allocated %p\n", mem);

		pwn::process::mem::write(mem, out);
		ok(L"written sc at %p\n", mem);
		::getchar();
		pwn::process::mem::free(mem);
	}


	if ( 0 )
	{
		std::string a("a");
		std::string b("b");
		auto args = std::vector<flattenable_t>{ a, b, (DWORD)1, (QWORD)1337 };
		auto out = pwn::utils::flatten(args);
		pwn::utils::hexdump(out);
	}


	if ( 0 )
	{
		// variant 1 of getsystem("notepad.exe") -> handle inheritance
		HANDLE hProcess;
		auto ppid = pwn::system::pidof(L"winlogon.exe");
		info(L"found winlogon pid=%lu\n", ppid);
		pwn::process::execv(L"cmd.exe", ppid, &hProcess);
		::WaitForSingleObject(hProcess, INFINITE);
		::CloseHandle(hProcess);
	}


	// test services
	if ( 0 )
	{
		for ( auto service : pwn::service::list() )
		{
			ok(L"Name='%s' Display='%s' Type=%d Status=%d\n", 
				service.Name.c_str(),
				service.DisplayName.c_str(),
				service.Type,
				service.Status
			);
		}
	}

	// test utils
	if (1)
	{
		for ( auto mod : pwn::kernel::modules() )
		{
			auto name = std::get<0>(mod);
			auto addr = std::get<1>(mod);
			ok(L"%s -> %p\n", name.c_str(), addr);
		}
		
	}
	ok(L"Done...\n");
	::getchar();

	return 0;
}