
## CTF stuff

Namespace: `pwn::ctf`

Description: Some pwntools goodies

```cpp
#include <pwn++\pwn.h>

using namespace pwn::log;
namespace ctx = pwn::context;
namespace ctf = pwn::ctf;
namespace utils = pwn::utils;

void wmain()
{
    ctx::set_log_level(LogLevel::Debug);
    {
        auto io = ctf::Remote(L"target_vm", 1337);
        io.recvuntil(">>> ");
        io.sendline("print('hi python')");
        io.recvuntil(">>> ");

        io.interactive();
        ok(L"done\n");
    }

    utils::pause();
}
```

Then the Linux tool `socat` can be used to bind easily a Python REPL to the TCP/1337 of `target_vm`

```bash
$ socat TCP-L:1337,fork,reuseaddr EXEC:/usr/bin/python3.8,pty,stderr
```

```text
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
