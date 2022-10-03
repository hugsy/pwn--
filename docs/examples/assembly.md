
## Disassembly

Powered by [capstone-engine](http://www.capstone-engine.org/)

```cpp
#include <pwn++\pwn.h>
int wmain()
{
    const uint8_t* code = "\x90\x48\x31\xc0\xcc\xc3";
    std::vector<pwn::disasm::insn_t> insns;
    pwn::disasm::x64(code, ::strlen(code), insns);
    for (auto insn : insns)
        ok(L"0x%08x:\t%s\t\t%s\n", insn.address, insn.mnemonic.c_str(), insn.operands.c_str());
    return 0;
}
```

Outputs
```
[+]  0x00040000:        nop
[+]  0x00040001:        xor             rax, rax
[+]  0x00040004:        int3
[+]  0x00040005:        ret
```
