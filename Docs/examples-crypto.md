
> Namespace `pwn::utils`
> Namespace `pwn::crypto`


### Hash functions

```cpp
#include <pwn++\pwn.h>

int wmain()
{
    std::vector<u8> data {0x41, 0x42, 0x43, 0x44} ;
    auto arr = pwn::crypto::sha256(data); // would work the same with `sha1`,`sha512`,`md5`,...
    std::vector<u8> vec (std::begin(arr), std::end(arr));
    pwn::utils::hexdump(vec);
    return 0;
}
```

```
0000   E1 2E 11 5A CF 45 52 B2  56 8B 55 E9 3C BD 39 39  |  ...Z.ER.V.U.<.99
0010   4C 4E F8 1C 82 44 7F AF  C9 97 88 2A 02 D2 36 77  |  LN...D.....*..6w
```

### Random

```cpp
#include <pwn++\pwn.h>

int wmain()
{
    ok(L"Next random is {:x}", pwn::utils::rand()) ;

    auto random_buffer = pwn::utils::buffer(32)) ;
    pwn::utils::hexdump(random_buffer);
    return 0;
}
```


```text
Next random is 0x8596dd0a5f
0000   66 24 7A 0E F5 B9 EB 91  A4 90 D5 DE F6 E5 CF 31  |  f$z............1
0010   24 EC A3 54 98 1F B1 B3  92 89 B7 E9 67 C8 BC BF  |  $..T........g...
```
