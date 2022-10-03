## Kernel stuff

Namespace: `pwn::kernel`

### Enumerate driver modules

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

### Steal token shellcode

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

