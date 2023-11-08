> Namespace `pwn::utils`

### pwntools cyclic()-like

```cpp
#include <pwn++\pwn.h>
int wmain()
{
    ok(L"pwntools.utils.cyclic() with a period of 4, and a length of 0x20 bytes\n");
    {
        auto res = pwn::utils::cyclic(0x20, 4);
        pwn::utils::hexdump(Value(res));
    }

    ok(L"nice, now with period=sizeof(PTR)\n");
    {
        auto res = pwn::utils::cyclic(0x30);
        pwn::utils::hexdump(Value(res));
    }

    return 0;
}
```

Outputs
```
[+] pwntools.utils.cyclic() with a period of 4, and a length of 0x20 bytes
0000   61 61 61 61 62 61 61 61  63 61 61 61 64 61 61 61  |  aaaabaaacaaadaaa
0010   65 61 61 61 66 61 61 61  67 61 61 61 68 61 61 61  |  eaaafaaagaaahaaa
[+] nice, now with period=sizeof(PTR)
0000   61 61 61 61 61 61 61 61  62 61 61 61 61 61 61 61  |  aaaaaaaabaaaaaaa
0010   63 61 61 61 61 61 61 61  64 61 61 61 61 61 61 61  |  caaaaaaadaaaaaaa
0020   65 61 61 61 61 61 61 61  66 61 61 61 61 61 61 61  |  eaaaaaaafaaaaaaa
```

### pwntools flat()-like

```cpp
#include <pwn++\pwn.h>

using namespace pwn::utils;

int wmain()
{
    std::string a("AAAA");
    std::wstring b(L"BBBB");

    auto args = std::vector<flattenable_t>{
        a,
        "AAAA",
        b,
        L"BBBB",
        p8(0x43),
        p8(0x43),
        p16(0x4343),
        p32(0x43434343),
        p64(0x4444444444444444)
    };

    hexdump( flatten(args) );
    return 0;
}
```

```
0000   41 41 41 41 41 41 41 41  42 00 42 00 42 00 42 00  |  AAAAAAAAB.B.B.B.
0010   42 00 42 00 42 00 42 00  43 43 43 43 43 43 43 43  |  B.B.B.B.CCCCCCCC
0020   44 44 44 44 44 44 44 44                           |  DDDDDDDD
```

### (bad) random stuff

```cpp
#include <pwn++\pwn.h>
int wmain()
{
    ok(L"random::byte=%x\n", pwn::utils::random::byte());
    ok(L"random::word=%x\n", pwn::utils::random::word());
    ok(L"random::dword=%x\n", pwn::utils::random::dword());
    ok(L"random::qword=%x\n", pwn::utils::random::qword());
    pwn::utils::hexdump(pwn::utils::random::buffer(16));
    ok(L"random::string=%s\n", pwn::utils::random::string(16).c_str());
    ok(L"random::alnum=%s\n", pwn::utils::random::alnum(16).c_str());
    return 0;
}
```

### Simple API import

using `ExportImport` macro, then copy/paste the definition (from MSDN, ReactOS, Pinvoke, NirSoft, etc.)

```cpp
#include <pwn>

ExportImport( \
    "ntdll.dll", \
    ZwCreateEnclave, \
    NTSTATUS, \
    HANDLE  hProcess, \
    LPVOID  lpAddress, \
    ULONGLONG ZeroBits, \
    SIZE_T  dwSize, \
    SIZE_T  dwInitialCommitment, \
    DWORD   flEnclaveType, \
    LPCVOID lpEnclaveInformation, \
    DWORD   dwInfoLength, \
    LPDWORD lpEnclaveError \
);

void wmain()
{
    auto addr = 0x010000;
    ENCLAVE_CREATE_INFO_VBS enc = {0};
    auto res = ZwCreateEnclave(
        ::GetCurrentProcess(),
        &addr,
        -1,
        0x1000,
        0x2000,
        ENCLAVE_TYPE_VBS,
        &enc,
        sizeof(enc),
        nullptr
    );
    if(res == STATUS_SUCCESS)
      ok(L"enclave allocated\n");
}
```

