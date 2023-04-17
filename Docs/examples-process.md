
## Process

### Current process info

```cpp
#include <pwn++\pwn.h>
void wmain()
{
    info(L"peb() is at %p\n", pwn::process::peb());
    info(L"teb() is at %p\n", pwn::process::teb());
}
```

### Process creation

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

### Process creation from specific parent

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
        auto h = pwn::UniqueHandle(hProcess.value());
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

### Terminate a process

```cpp
#include <pwn++\pwn.h>
int wmain()
{
    auto hProcess = pwn::process::execv(L"notepad.exe hello.txt");
    if ( hProcess )
    {
        auto h = pwn::UniqueHandle(hProcess.value());
        ::Sleep(5*1000);
        pwn::process::kill(h.get());
    }
}
```

### Privileges

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


### Integrity

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


### Memory access

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

## Enumerate all processes

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


### Simple AppContainer


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

