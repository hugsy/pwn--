> Namespace `pwn`


```cpp
#include <pwn++\pwn.h>

using namespace pwn;

auto wmain() -> int
{
    auto const [major, minor] = pwn::VersionInfo;
    ok(L"Running pwn++ v{:d}.{:02d}", major, minor);

    Context.set("x64");
    dbg(L"The default log_level is INFO, this message will not show!");

    Context.set_log_level(log::LogLevel::Debug);
    dbg(L"Now it will!");

    try
    {
        Context.set("whatever_arch_that_dont_exist");
    }
    catch(...)
    {
        err(L"Wattya doin' there?");
    }

    info(L"Using arch {}", Context.architecture);

    ok(L"Everything is awesome!");
    warn(L"Alright, stop! Collaborate and listen...");
    err(L"Can't touch this!");
    return 0;
}
```

Will output:

```
PS C:\Users\User> .\test.exe
[+]  Running pwn++ v0.13
[DEBUG]  log_level set to 0
[DEBUG]  Now it will!
[-] Wattya doin' there?
[+] Using arch Architecture(x64, ptrsize=8, endian=LITTLE)
[+] Everything is awesome!
[!] Alright, stop! Collaborate and listen...
[-] Can't touch this!
```
