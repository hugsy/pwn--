## Context & logging

```cpp
#include <pwn++\pwn.h>
namespace ctx = pwn::context;
auto wmain() -> int
{
    auto const [major, minor] = pwn::version_info();
    ok(L"running pwn++ v{:d}.{:02d}", major,minor);

    ctx::set_arch("x64");

    dbg(L"The default log_level is INFO, this message will never appear!\n");
    ctx::set_log_level(pwn::log::LogLevel::Debug);
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
`