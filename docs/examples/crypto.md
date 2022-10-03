
## Crypto

### Hash functions

```cpp
#include <pwn++\pwn.h>
auto wmain() -> void
{
    std::vector<BYTE> data {0x41, 0x42, 0x43, 0x44} ;
    auto arr = pwn::crypto::sha256(data); // would work the same with `sha1`,`sha512`,`md5`,...
    std::vector<BYTE> vec (std::begin(arr), std::end(arr));
    pwn::utils::hexdump(m);
}
```

```
0000   E1 2E 11 5A CF 45 52 B2  56 8B 55 E9 3C BD 39 39  |  ...Z.ER.V.U.<.99
0010   4C 4E F8 1C 82 44 7F AF  C9 97 88 2A 02 D2 36 77  |  LN...D.....*..6w
```

