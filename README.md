# pwn++

A (bad) C++17 rewrite of my [PwnLib](https://github.com/hugsy/pwnlib) DLL for Windows.

The idea is to provide in C on Windows the same kind of functionalities than [pwntools](https://github.com/Gallopsled/pwntools) does in Python on Linux.
It's also a toy library meant for exploring Windows in a more friendly way. So if you're looking for years of poorly written C/C++ tangled with performant
inefficient ways to explore Windows at low-level, go no further friend this library is for you.

_Note_: my old original pwnlib was written around Windows 7 for feature testing. This is 100% Windows 10 focused, so expect things to go wrong if you use any
other Windows version. It's by design.


## Requirement

MS VC 16+ Redistributable:
 - [x64](https://aka.ms/vs/16/release/vc_redist.x64.exe)
 - [x86](https://aka.ms/vs/16/release/vc_redist.x86.exe)


## Get started

### Quick Start

To start using, simply include `pwn.h` and link with `pwn++.dll`.

```cpp
#include "path\to\pwn.h"
#pragma comment(lib, "\path\to\pwn.lib")
```

Then compile your binary linked with the lib (make sure you're C++17 compliant):

```bash
C:\> cl.exe whatever.cc /std:c++17
C:\> clang.exe whatever.cc -std=++17
```

### Better start

Or better, use Visual Studio and add it via the GUI (this approach has the huge advantage that you can rely on IntelliSense for auto-completion). In VS, go to
right click on your project in the `Solution Explorer` -> `Properties, then:
 - add `pwn++` location to `C/C++`->`General`->`Additional Include Directories`
 - add `pwn++` library location to `Linker`->`General`->`Additional Libraries Directories`
 - add `pwn++.lib` to `Linker`->`Input`->`Additional Dependencies`

To compile, just build your project/solution.


## Examples

Basic examples of what the lib offers:


### Context

```cpp
#include <pwn++\pwn.h>
auto wmain()
{
	auto version = pwn::version_info();
	ok(L"running pwn++ v%d.%02d\n", std::get<0>(version), std::get<1>(version));

	pwn::context::set_arch(pwn::context::arch_t::x64);
	pwn::context::set_log_level(pwn::log::log_level_t::LOG_DEBUG);

	return 0;
}
```

Outputs
```
PS C:\Users\User> .\test.exe
[+]  running pwn++ v0.01
[DEBUG]  log_level set to 0
```


### Utils

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
	const uint8_t* code = "xor rax, rax; inc rax; nop; ret";
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

#### Process creation from specific parent

Cheap way to spawn a `NT AUTHORITY\SYSTEM` process from Admin prompt

```cpp
#include <pwn++\pwn.h>
int wmain()
{
	HANDLE hProcess;B
	auto ppid = pwn::system::pidof(L"winlogon.exe");
	info(L"found winlogon pid=%lu\n", ppid);
	pwn::process::execv(L"cmd.exe", ppid, &hProcess);
	::CloseHandle(hProcess);
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
