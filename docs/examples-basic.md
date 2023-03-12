
## Basic

Namespace `pwn::Assembly`

The most basic example for using `pwn++`.

```cpp
// 1. include the header
#include <pwn.hpp>
// 2. invoke the namespace
using namespace pwn;
// 3. that's it!

int wmain()
{
    ok("I can haz more pwn++");
    return 0;
}
```

Outputs
```
[+]  0x00040000:        nop
[+]  0x00040001:        xor             rax, rax
[+]  0x00040004:        ret
[+]  0x00040005:        int3
```
