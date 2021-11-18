# pwn++


| View | Code | Build | Talk |
|:---:|:---:|:---:|:---:|
| [![Read code](https://img.shields.io/badge/Code-Read%20pwn++-brightgreen?logo=visualstudiocode)](https://github.dev/hugsy/pwn--) | [![Open in Visual Studio Code](https://open.vscode.dev/badges/open-in-vscode.svg)](https://open.vscode.dev/hugsy/pwn--) | [![CI - MSVC](https://github.com/hugsy/pwn--/workflows/CI%20Build%20for%20MSVC/badge.svg)](https://github.com/hugsy/pwn--/actions?query=workflow%3A%22CI+Build+for+MSVC%22) | [![Discord](https://img.shields.io/badge/Discord-pwn%2b%2b-purple)](https://discord.gg/5HmwPxy3HP) |


A (bad) C++17 rewrite of my [PwnLib](https://github.com/hugsy/pwnlib) DLL, battery-included pwn kit for Windows.

The idea is to provide in C on Windows the same kind of functionalities than [pwntools](https://github.com/Gallopsled/pwntools) does in Python on Linux.
It's also a toy library meant for exploring Windows in a more friendly way. So if you're looking for years of poorly written C/C++ tangled with performant
inefficient ways to explore Windows at low-level, go no further friend this library is for you.

_Note_: the original `PwnLib` was written around Windows 7 for feature testing. This is 100% Windows 10 focused, so expect things to go wrong if you use any other Windows version. Some stuff may also go wrong in x86. Better use 64. It's not a bug but a design choice 😋


## Requirement

### Windows

 - x86 → [MSVC 16+ x86 Redistributable](https://aka.ms/vs/16/release/vc_redist.x86.exe)
 - x64 → [MSVC 16+ x64 Redistributable](https://aka.ms/vs/16/release/vc_redist.x64.exe)


### Linux
 
  - None (AFAIK)
  

## Get started

### Quick Start

To start using `pwn++` lib, simply download the latest successful build from [CI builds](https://github.com/hugsy/pwn--/actions/workflows/msvc-build.yml?query=is%3Asuccess), download and extract the zip file.
In your C++ file, just include `pwn.h` and link with `pwn++.dll`.

```cpp
#include "path\to\pwn++\pwn.h"
#pragma comment(lib, "\path\to\pwn++\pwn.lib")
```

Then compile your binary linked with the lib (make sure you're at least C++17 compliant):

```bash
C:\> cl.exe whatever.cc /std:c++17
C:\> clang.exe whatever.cc -std=c++17
```

### Better start

Or better, use Visual Studio and add it via the GUI (this approach has the huge advantage that you can rely on IntelliSense for auto-completion). In Visual Studio,
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
	ctx::set_log_level(pwn::log::log_level_t::LOG_DEBUG);
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

using namespace pwn::utils;

int wmain()
{
	std::string a("AAAA");
	std::wstring b(L"BBBB");

	auto args = std::vector<flattenable_t>{
		a,
		"AAAA",
		b,
		L"BBBB",
		p8(0x43),
		p8(0x43),
		p16(0x4343),
		p32(0x43434343),
		p64(0x4444444444444444)
	};

	hexdump( flatten(args) );
	return 0;
}
```

```
0000   41 41 41 41 41 41 41 41  42 00 42 00 42 00 42 00  |  AAAAAAAAB.B.B.B.
0010   42 00 42 00 42 00 42 00  43 43 43 43 43 43 43 43  |  B.B.B.B.CCCCCCCC
0020   44 44 44 44 44 44 44 44                           |  DDDDDDDD
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

Or `ShellExecute` style:

```cpp
#include <pwn++\pwn.h>
int wmain()
{
	pwn::process::system(L"ms-settings:");
	return 0;
}
```

#### Process creation from specific parent

Cheap way to spawn a `NT AUTHORITY\SYSTEM` process from Admin prompt

```cpp
#include <pwn++\pwn.h>
int wmain()
{
	auto ppid = pwn::system::pidof(L"winlogon.exe");
	info(L"found winlogon pid=%lu\n", ppid);
	auto hProcess = pwn::process::execv(L"cmd.exe", ppid);
	if(hProcess)
	{
		auto h = pwn::utils::GenericHandle(hProcess.value());
		::WaitForSingleObject(h.get(), INFINITE);
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
	auto hProcess = pwn::process::execv(L"notepad.exe hello.txt");
	if ( hProcess )
	{
		auto h = pwn::utils::GenericHandle(hProcess.value());
		::Sleep(5*1000);
		pwn::process::kill(h.get());
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
	auto integrity = pwn::process::get_integrity_level();
	if ( integrity )
		ok(L"integrity set to '%s'\n", integrity.value().c_str());
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


```cpp
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

Namespace: `pwn::kernel`

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

Namespace: `pwn::windows::service`

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

Namespace: `pwn::windows::alpc`


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
		pwn::windows::alpc::client::connect(L"\\RPC Control\\lotzofun")
	);

	if ( client )
	{
		ok(L"client connected to epmapper (handle=%p)\n", client.Get());
		pwn::windows::alpc::send_and_receive(client, { 0x41, 0x41, 0x41, 0x41 });
		// pwn::windows::alpc::close(client); // not necessary because of RAII
	}
}
```

### Crypto

#### Hash functions

```cpp
#include <pwn++\pwn.h>
auto wmain() -> void
{
    std::vector<BYTE> data {0x41, 0x42, 0x43, 0x44} ;
    auto arr = pwn::crypto::sha256(data); // would work the same with `sha1`,`sha512`,`md5`,...
    std::vector<BYTE> vec (std::begin(arr), std::end(arr));
    pwn::utils::hexdump(m);
}
```

```
0000   E1 2E 11 5A CF 45 52 B2  56 8B 55 E9 3C BD 39 39  |  ...Z.ER.V.U.<.99
0010   4C 4E F8 1C 82 44 7F AF  C9 97 88 2A 02 D2 36 77  |  LN...D.....*..6w
```


### File System

#### Create directories

Temporary

```cpp
#include <pwn++\pwn.h>
auto wmain() -> int
{
	try
	{
		auto d = pwn::fs::make_tmpdir()
		ok(L"created temp dir %s\n", d);
	}
	catch(...){}
	return 0;
}
```


Recursively
```cpp
#include <pwn++\pwn.h>

auto wmain() -> int
{
	if (!pwn::fs::mkdir(L"a\\crazy\\path\\that\\doesnt\\exist"))
		perror(L"fs::mkdir()");
	return 0;
}
```


#### Monitor directory

```cpp
#include <pwn++\pwn.h>

auto wmain() -> int
{
    auto lambda_func = [](PFILE_NOTIFY_INFORMATION info)
    {
        switch(info->Action)
        {
        case FILE_ACTION_ADDED:              ok(L"FILE_ACTION_ADDED '%s'\n", info->FileName); break;
        case FILE_ACTION_REMOVED:            ok(L"FILE_ACTION_REMOVED '%s'\n", info->FileName); break;
        case FILE_ACTION_MODIFIED:           ok(L"FILE_ACTION_MODIFIED '%s'\n", info->FileName); break;
        case FILE_ACTION_RENAMED_OLD_NAME:   ok(L"FILE_ACTION_RENAMED_OLD_NAME '%s'\n", info->FileName); break;
        case FILE_ACTION_RENAMED_NEW_NAME:   ok(L"FILE_ACTION_RENAMED_NEW_NAME '%s'\n", info->FileName); break;
		default: return false;
        }
        return true;
    };

    if (!pwn::fs::watch_dir(L"c:\\windows\\system32", lambda_func))
        perror(L"watch_dir");

    return 0;
}
```

#### Create a symlink


```cpp
#include <pwn++\pwn.h>

auto wmain() -> int
{
	{
		if(!pwn::utils::GenericHandle( pwn::fs::touch(L"myfile.txt") ))
			return -1;
	}

	auto l = pwn::utils::GenericHandle( pwn::fs::create_symlink(L"mylink.txt", L"myfile.txt") );
	if(!l)
		return -2;

	ok(L"created link '%s' -> '%s'\n", L"mylink.txt", L"myfile.txt");

	return 0;
}
```

#### Create a junction


```cpp
#include <pwn++\pwn.h>

auto wmain() -> int
{
    // todo
    return 0;
}
```


### Simple API import

using `IMPORT_EXTERNAL_FUNCTION` macro, then copy/paste the definition (from MSDN, ReactOS, Pinvoke, NirSoft, etc.)

```c
#include <pwn++\pwn.h>

IMPORT_EXTERNAL_FUNCTION( \
	L"ntdll.dll", \
	ZwCreateEnclave, \
	NTSTATUS, \
	HANDLE  hProcess, \
	LPVOID  lpAddress, \
	ULONGLONG ZeroBits, \
	SIZE_T  dwSize, \
	SIZE_T  dwInitialCommitment, \
	DWORD   flEnclaveType, \
	LPCVOID lpEnclaveInformation, \
	DWORD   dwInfoLength, \
	LPDWORD lpEnclaveError \
);

void wmain()
{
	auto addr = 0x010000;
	ENCLAVE_CREATE_INFO_VBS enc = {0};
	auto res = ZwCreateEnclave(
		::GetCurrentProcess(),
		&addr,
		-1,
		0x1000,
		0x2000,
		ENCLAVE_TYPE_VBS,
		&enc,
		sizeof(enc),
		nullptr
	);
	if(res == STATUS_SUCCESS)
	  ok(L"enclave allocated\n");
}
```


### CTF stuff

Namespace: `pwn::ctf`

Description: Some pwntools goodies (WIP)

```cpp
#include <pwn++\pwn.h>

using namespace pwn::log;
namespace ctx = pwn::context;
namespace ctf = pwn::ctf;
namespace utils = pwn::utils;

void wmain()
{
    ctx::set_log_level(log_level_t::LOG_DEBUG);
    {
        auto io = ctf::Remote(L"target", 1337);
        io.recvuntil(">>> ");
        io.sendline("print('hi python')");
        io.recvuntil(">>> ");

        io.interactive();
        ok(L"done\n");
    }

    utils::pause();
}
```

```
[DEBUG]  log_level set to LOG_LEVEL_DEBUG (0)
[DEBUG]  connected to 192.168.57.64:1337
[DEBUG]  recv 46 bytes
0000   50 79 74 68 6F 6E 20 33  2E 38 2E 35 20 28 64 65  |  Python 3.8.5 (de
0010   66 61 75 6C 74 2C 20 4A  61 6E 20 32 37 20 32 30  |  fault, Jan 27 20
0020   32 31 2C 20 31 35 3A 34  31 3A 31 35 29 20        |  21, 15:41:15)
[DEBUG]  recv 100 bytes
0000   0D 0A 5B 47 43 43 20 39  2E 33 2E 30 5D 20 6F 6E  |  ..[GCC 9.3.0] on
0010   20 6C 69 6E 75 78 0D 0A  54 79 70 65 20 22 68 65  |   linux..Type "he
0020   6C 70 22 2C 20 22 63 6F  70 79 72 69 67 68 74 22  |  lp", "copyright"
0030   2C 20 22 63 72 65 64 69  74 73 22 20 6F 72 20 22  |  , "credits" or "
0040   6C 69 63 65 6E 73 65 22  20 66 6F 72 20 6D 6F 72  |  license" for mor
0050   65 20 69 6E 66 6F 72 6D  61 74 69 6F 6E 2E 0D 0A  |  e information...
0060   3E 3E 3E 20                                       |  >>>
[DEBUG]  sent 13 bytes
0000   70 72 69 6E 74 28 27 31  2B 31 27 29 0A           |  print('1+1').
[DEBUG]  recv 23 bytes
0000   70 72 69 6E 74 28 27 31  2B 31 27 29 0D 0A 31 2B  |  print('1+1')..1+
0010   31 0D 0A 3E 3E 3E 20                              |  1..>>>
[INFO]  Entering interactive mode...
>>> import sys
[DEBUG]  sent 11 bytes
0000   69 6D 70 6F 72 74 20 73  79 73 0A                 |  import sys.
>>> [DEBUG]  recv 16 bytes
0000   69 6D 70 6F 72 74 20 73  79 73 0D 0A 3E 3E 3E 20  |  import sys..>>>
[...]
```
