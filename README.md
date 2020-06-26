# pwn++


[![CI - MSVC](https://github.com/hugsy/pwn--/workflows/CI%20Build%20for%20MSVC/badge.svg)](https://github.com/hugsy/pwn--/actions?query=workflow%3A%22CI+Build+for+MSVC%22)


A (bad) C++17 rewrite of my [PwnLib](https://github.com/hugsy/pwnlib) DLL for Windows.

The idea is to provide in C on Windows the same kind of functionalities than [pwntools](https://github.com/Gallopsled/pwntools) does in Python on Linux.
It's also a toy library meant for exploring Windows in a more friendly way. So if you're looking for years of poorly written C/C++ tangled with performant
inefficient ways to explore Windows at low-level, go no further friend this library is for you.

_Note_: the original `PwnLib` was written around Windows 7 for feature testing. This is 100% Windows 10 focused, so expect things to go wrong if you use any other Windows version. Some stuff may also go wrong in x86. Better use 64. It's not a bug but a design choice 😋


## Requirement

MS VS 16+ Redistributable:
 - [x64](https://aka.ms/vs/16/release/vc_redist.x64.exe)
 - [x86](https://aka.ms/vs/16/release/vc_redist.x86.exe)


## Get started

### Quick Start

To start using, simply include `pwn.h` and link with `pwn++.dll`.

```cpp
#include "path\to\pwn++\pwn.h"
#pragma comment(lib, "\path\to\pwn++\pwn.lib")
```

Then compile your binary linked with the lib (make sure you're C++17 compliant):

```bash
C:\> cl.exe whatever.cc /std:c++17
C:\> clang.exe whatever.cc -std=++17
```

### Better start

Or better, use Visual Studio and add it via the GUI (this approach has the huge advantage that you can rely on IntelliSense for auto-completion). In VS, go to
right click on your project in the `Solution Explorer` -> `Properties`, then:
 - add `pwn++` location to `C/C++`->`General`->`Additional Include Directories`
 - add `pwn++` library location to `Linker`->`General`->`Additional Libraries Directories`
 - add `pwn++.lib` to `Linker`->`Input`->`Additional Dependencies`

To compile, just build your project/solution.


## Examples

Basic examples of what the lib offers:


### Context & logging

```cpp
#include <pwn++\pwn.h>
namespace ctx = pwn::context;
auto wmain() -> int
{
	auto version = pwn::version_info();
	ok(L"running pwn++ v%d.%02d\n", std::get<0>(version), std::get<1>(version));

	ctx::set_arch(pwn::context::arch_t::x64);

	dbg(L"The default log_level is INFO, this message will never appear!\n");
	ctx:set_log_level(pwn::log::log_level_t::LOG_DEBUG);
	dbg(L"Now it will!\n");

	ok(L"Everything is awesome!\n");
	warn(L"Alright, stop! Collaborate and listen...\n");
	err(L"Can't touch this!\n");
	return 0;
}
```

Outputs

```
PS C:\Users\User> .\test.exe
[+]  running pwn++ v0.01
[DEBUG]  log_level set to 0
[DEBUG]  Now it will!
[+] Everything is awesome!
[!] Alright, stop! Collaborate and listen...
[-] Can't touch this!
```


### Utils

#### pwntools cyclic()-like

```cpp
#include <pwn++\pwn.h>
int wmain()
{
	std::vector<BYTE> buf;

	ok(L"pwntools.utils.cyclic() with a period of 4, and a length of 0x20 bytes\n");
	if ( pwn::utils::cyclic(0x20, 4, buf) )
		pwn::utils::hexdump(buf);

	ok(L"nice, now with period=sizeof(PTR)\n");
	if ( pwn::utils::cyclic(0x30, buf) )
		pwn::utils::hexdump(buf);

	return 0;
}
```

Outputs
```
[+] pwntools.utils.cyclic() with a period of 4, and a length of 0x20 bytes
0000   61 61 61 61 62 61 61 61  63 61 61 61 64 61 61 61  |  aaaabaaacaaadaaa
0010   65 61 61 61 66 61 61 61  67 61 61 61 68 61 61 61  |  eaaafaaagaaahaaa
[+] nice, now with period=sizeof(PTR)
0000   61 61 61 61 61 61 61 61  62 61 61 61 61 61 61 61  |  aaaaaaaabaaaaaaa
0010   63 61 61 61 61 61 61 61  64 61 61 61 61 61 61 61  |  caaaaaaadaaaaaaa
0020   65 61 61 61 61 61 61 61  66 61 61 61 61 61 61 61  |  eaaaaaaafaaaaaaa
```

#### pwntools flat()-like

```cpp
#include <pwn++\pwn.h>
int wmain()
{
	std::string a("a");
	std::string b("b");
	auto args = std::vector<flattenable_t>{ a, b, (DWORD)1, (QWORD)1337 };
	auto out = pwn::utils::flatten(args);
	pwn::utils::hexdump(out);
	return 0;
}
```


#### (bad) random stuff

```cpp
#include <pwn++\pwn.h>
int wmain()
{
	ok(L"random::byte=%x\n", pwn::utils::random::byte());
	ok(L"random::word=%x\n", pwn::utils::random::word());
	ok(L"random::dword=%x\n", pwn::utils::random::dword());
	ok(L"random::qword=%x\n", pwn::utils::random::qword());
	pwn::utils::hexdump(pwn::utils::random::buffer(16));
	ok(L"random::string=%s\n", pwn::utils::random::string(16).c_str());
	ok(L"random::alnum=%s\n", pwn::utils::random::alnum(16).c_str());
	return 0;
}
```

### System information

```cpp
#include <pwn++\pwn.h>
int wmain()
{
	info(L"computer_name=%s\n", pwn::system::name().c_str());
	info(L"pagesize=0x%x\n", pwn::system::pagesize());
	info(L"pid=%d\n", pwn::process::pid());
	info(L"ppid=%d\n", pwn::process::ppid());
	info(L"pidof('explorer.exe')=%d\n", pwn::system::pidof(std::wstring(L"explorer.exe"));
	info(L"nb_cores=%ld\n", pwn::cpu::nb_cores());
	return 0;
}
```



### Disassembly

Powered by [capstone-engine](http://www.capstone-engine.org/)

```cpp
#include <pwn++\pwn.h>
int wmain()
{
	const uint8_t* code = "\x90\x48\x31\xc0\xcc\xc3";
	std::vector<pwn::disasm::insn_t> insns;
	pwn::disasm::x64(code, ::strlen(code), insns);
	for (auto insn : insns)
		ok(L"0x%08x:\t%s\t\t%s\n", insn.address, insn.mnemonic.c_str(), insn.operands.c_str());
	return 0;
}
```

Outputs
```
[+]  0x00040000:        nop
[+]  0x00040001:        xor             rax, rax
[+]  0x00040004:        int3
[+]  0x00040005:        ret
```


### Assembly

Powered by [keystone-engine](http://www.keystone-engine.org/)

```cpp
#include <pwn++\pwn.h>
int wmain()
{
	const uint8_t code[] = "xor rax, rax; inc rax; nop; ret";
	std::vector<BYTE> bytes;
	pwn::assm::x64(code, ::strlen(code), bytes);
	pwn::utils::hexdump(bytes);
	return 0;
}
```

Outputs
```
0000   48 31 C0 48 FF C0 90 C3                           |  H1.H....
```

### Process

#### Current process info

```cpp
#include <pwn++\pwn.h>
void wmain()
{
	info(L"peb() is at %p\n", pwn::process::peb());
	info(L"teb() is at %p\n", pwn::process::teb());
}
```

#### Process creation

Via `pwn::process::execv()`, basic wrapper over `::CreateProcess()`

```cpp
#include <pwn++\pwn.h>
int wmain()
{
	return pwn::process::execv(L"cmd.exe") == TRUE;
}
```

#### Process creation from specific parent

Cheap way to spawn a `NT AUTHORITY\SYSTEM` process from Admin prompt

```cpp
#include <pwn++\pwn.h>
int wmain()
{
	HANDLE hProcess;
	auto ppid = pwn::system::pidof(L"winlogon.exe");
	info(L"found winlogon pid=%lu\n", ppid);
	if(pwn::process::execv(L"cmd.exe", ppid, &hProcess))
	{
		auto h = pwn::utils::GenericHandle(hProcess);
		::CloseHandle(h.Get());
	}
	return 0;
}
```

Outputs
```
REM In Prompt
PS C:\> whoami
Win10Eval2019\hugsy
PS C:\> .\pwn++-tests.exe
[DEBUG]  log_level set to 0
[*]  found winlogon pid=684
[DEBUG]  Spawning 'cmd.exe' with PPID=684...
[DEBUG]  'cmd.exe' spawned with PID 2024

REM New prompt appears
C:\Windows\System32>whoami
nt authority\system
```

#### Terminate a process

```cpp
#include <pwn++\pwn.h>
int wmain()
{
	HANDLE hProcess;
	if ( pwn::process::execv(L"notepad.exe hello.txt", &hProcess) )
	{
		auto h = pwn::utils::GenericHandle(hProcess);
		::Sleep(5*1000);
		pwn::process::kill(h.Get());
	}
}
```

#### Privileges

```cpp
#include <pwn++\pwn.h>
void wmain()
{
	auto pid = pwn::system::pidof(L"explorer.exe");
	ok(L"is_elevated: %s\n", BOOL_AS_STR(pwn::process::is_elevated(pid)));
	ok(L"has_privilege(SeDebugPrivilege): %s\n", BOOL_AS_STR(pwn::process::has_privilege(L"SeDebugPrivilege", pid)));
	ok(L"has_privilege(SeChangeNotifyPrivilege): %s\n", BOOL_AS_STR(pwn::process::has_privilege(L"SeChangeNotifyPrivilege", pid)));
}
```


#### Integrity

```cpp
#include <pwn++\pwn.h>
void wmain()
{
	std::wstring integrity;
	if ( pwn::process::get_integrity_level(integrity) == ERROR_SUCCESS )
		ok(L"integrity set to '%s'\n", integrity.c_str());
	else
		perror(L"pwn::process::get_integrity_level()");
}
```


#### Memory access

```cpp
#include <pwn++\pwn.h>

void wmain()
{
	/// against a specific process
	auto peb_loc = (ULONG_PTR)pwn::process::peb();
	auto peb_cnt = pwn::process::mem::read(peb_loc, 0x10);
	pwn::utils::hexdump(peb_cnt);
	std::vector<BYTE> new_peb = { 0x13, 0x37, 0x13, 0x37 };
	pwn::process::mem::write(peb_loc, new_peb);
	peb_cnt = pwn::process::mem::read(peb_loc, 0x10);
	pwn::utils::hexdump(peb_cnt);

	/// or on this process
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
```

#### Simple AppContainer


```
#include <pwn++\pwn.h>

void wmain()
{
  auto container_name { L"container-" + pwn::utils::random::alnum(10) };
  pwn::process::appcontainer::AppContainer app(container_name, "notepad.exe");
  app.spawn();
}
```

Also supports capabilities, see [`AppContainMe`](/AppContainMe) for a better example.


### Jobs

```cpp
#include <pwn++\pwn.h>

void wmain()
{
	/// create a notepad process and add it to an anonymous job
	HANDLE hProcess;
	auto ppid = pwn::process::ppid();
	if( pwn::process::execv(L"notepad.exe", ppid, &hProcess) )
	{
		auto hp = pwn::utils::GenericHandle(hProcess);

		auto hJob = pwn::utils::GenericHandle( pwn::job::create() );
		if( hJob )
		{
			auto pid = pwn::system::pid(hp.Get());
			pwn::job::add_process(hJob, pid);
			::WaitForSingleObject(hp.Get(), INFINITE);
		}

		// pwn::job::close(hJob); // not necessary because of RAII
	}
}
```

### Registry

```cpp
#include <pwn++\pwn.h>

void wmain()
{
	/// dword value
	{
	std::wstring sub_key(L"Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon");
	std::wstring reg_dword(L"FirstLogon");
	DWORD value = -1;
	if ( pwn::reg::read_dword(pwn::reg::hkcu(), sub_key, reg_dword, &value) == ERROR_SUCCESS )
		ok(L"FirstLogon=%d\n", value);
	}

	/// string value
	{
		std::wstring sub_key(L"SYSTEM\\Software\\Microsoft");
		std::wstring reg_sz(L"BuildLab");
		std::wstring BuildLab;
		if ( pwn::reg::read_wstring(pwn::reg::hklm(), sub_key, reg_sz, BuildLab) == ERROR_SUCCESS )
			ok(L"BuildLab=%s\n", BuildLab.c_str());
	}

	/// binary value
	{
		std::wstring sub_key(L"SYSTEM\\RNG");
		std::wstring reg_sz(L"Seed");
		std::vector<BYTE> Seed;
		if ( pwn::reg::read_binary(pwn::reg::hklm(), sub_key, reg_sz, Seed) == ERROR_SUCCESS )
			pwn::utils::hexdump(Seed);
	}
```



#### Enumerate all processes

`pwn::process::list()`

```cpp
#include <pwn++\pwn.h>

void wmain()
{
	for ( auto& p : pwn::process::list() )
	{
		std::wstring integrity;
		pwn::process::get_integrity_level(p.pid, integrity);
		ok(L"%d -> %s (i=%s)\n", p.pid, p.name.c_str(), integrity.c_str());
	}
}
```


### Kernel stuff

#### Enumerate driver modules

```cpp
#include <pwn++\pwn.h>

void wmain()
{
	for ( auto& mod : pwn::kernel::modules() )
	{
		auto name = std::get<0>(mod);
		auto addr = std::get<1>(mod);
		ok(L"%s -> %p\n", name.c_str(), addr);
	}
}
```

#### Steal token shellcode

```cpp
#include <pwn++\pwn.h>

void wmain()
{
	auto out = pwn::kernel::shellcode::steal_system_token();
	ok(L"compiled sc:\n");
	pwn::utils::hexdump(out);
	auto mem = pwn::process::mem::alloc(0x1000, L"rwx");
	ok(L"allocated %p\n", mem);
	pwn::process::mem::write(mem, out);
	ok(L"written sc at %p\n", mem);
	pwn::process::mem::free(mem);
}
```


### Service

#### Enumerate

```cpp
#include <pwn++\pwn.h>

void wmain()
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
```



### ALPC

#### Server
```cpp
#include <pwn++\pwn.h>

void wmain()
{
	auto server = pwn::utils::GenericHandle(
		pwn::windows::alpc::server::listen(L"\\RPC Control\\lotzofun")
	);

	if ( server )
	{
		ok(L"server created port (handle=%p)\n", server.Get());
		auto recv = pwn::windows::alpc::send_and_receive(server.Get());
		// pwn::windows::alpc::close(server); // not necessary because of RAII
	}
}
```


#### Client

```cpp
#include <pwn++\pwn.h>

void wmain()
{
	auto client = pwn::utils::GenericHandle(
		pwn::windows::alpc::client::connect(L"\\RPC Control\\epmapper")
	);

	if ( client )
	{
		ok(L"client connected to epmapper (handle=%p)\n", client.Get());
		pwn::windows::alpc::send_and_receive(client, { 0x41, 0x41, 0x41, 0x41 });
		// pwn::windows::alpc::close(client); // not necessary because of RAII
	}
}
```
