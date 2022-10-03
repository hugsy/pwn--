

## System information

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
