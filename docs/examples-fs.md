
## File System

### Create directories

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


### Monitor directory

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

### Create a symlink


```cpp
#include <pwn++\pwn.h>

auto wmain() -> int
{
    {
        if(!pwn::UniqueHandle( pwn::fs::touch(L"myfile.txt") ))
            return -1;
    }

    auto l = pwn::UniqueHandle( pwn::fs::create_symlink(L"mylink.txt", L"myfile.txt") );
    if(!l)
        return -2;

    ok(L"created link '%s' -> '%s'\n", L"mylink.txt", L"myfile.txt");

    return 0;
}
```

### Create a junction


```cpp
#include <pwn++\pwn.h>

auto wmain() -> int
{
    // todo
    return 0;
}
```

