
## Jobs

```cpp
#include <pwn++\pwn.h>

void wmain()
{
    /// create a notepad process and add it to an anonymous job
    HANDLE hProcess;
    auto ppid = pwn::process::ppid();
    if( pwn::process::execv(L"notepad.exe", ppid, &hProcess) )
    {
        auto hp = pwn::UniqueHandle(hProcess);

        auto hJob = pwn::UniqueHandle( pwn::job::create() );
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
