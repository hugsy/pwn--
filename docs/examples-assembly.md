
## Disassembly

Namespace `pwn::Assembly`


Powered by [Zydis](https://github.com/zyantific/zydis) for x86/x64 - [binja-arm64](https://github.com/Vector35/arch-arm64) for arm64

```cpp
#include <pwn++\pwn.h>

int wmain()
{
    const u8* code = "\x90\x48\x31\xc0\xc3\xcc";
    auto WantedArch = Architecture::Find("x64");
    pwn::Assembly::Disassembler d{WantedArch};
    d.SetOffset(0);
    auto res = d.DisassembleUntil(
        code,
        [](auto const& i)
        {
            return i.o.x86.mnemonic == ZydisMnemonic::ZYDIS_MNEMONIC_INT3;
        }
    );

    auto insn_str_vec = pwn::Assembly::Disassembler::Format(Value(res), 0x00040000);
    for (auto const& insn_str : Value(insn_str_vec))
    {
        ok("{}", insn_str);
    }

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
