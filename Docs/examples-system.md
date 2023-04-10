

## System information

```cpp
#include <pwn++\pwn.h>
int wmain()
{
    info(L"Computer name = {}", pwn::windows::System.ComputerName().c_str());
    info(L"Page size = {:x}", pwn::windows::System.PageSize());
    info(L"PID = {}", pwn::windows::System.ProcessId(::GetCurrentProcess()));
    info(L"PPID = {}", pwn::windows::System.ParentProcessId(::GetCurrentProcessId()));
    info(L"pidof('explorer.exe') = {}", pwn::windows::System.PidOf(L"explorer.exe")[0]);
    info(L"ProcessorCount = {}", pwn::windows::System.ProcessorCount());
    return 0;
}
```
