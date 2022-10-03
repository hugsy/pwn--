
## Registry

```cpp
#include <pwn++\pwn.h>

void wmain()
{
    /// dword value
    {
    std::wstring sub_key(L"Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon");
    std::wstring reg_dword(L"FirstLogon");
    DWORD value = -1;
    if ( pwn::reg::read_dword(pwn::reg::hkcu(), sub_key, reg_dword, &value) == ERROR_SUCCESS )
        ok(L"FirstLogon=%d\n", value);
    }

    /// string value
    {
        std::wstring sub_key(L"SYSTEM\\Software\\Microsoft");
        std::wstring reg_sz(L"BuildLab");
        std::wstring BuildLab;
        if ( pwn::reg::read_wstring(pwn::reg::hklm(), sub_key, reg_sz, BuildLab) == ERROR_SUCCESS )
            ok(L"BuildLab=%s\n", BuildLab.c_str());
    }

    /// binary value
    {
        std::wstring sub_key(L"SYSTEM\\RNG");
        std::wstring reg_sz(L"Seed");
        std::vector<BYTE> Seed;
        if ( pwn::reg::read_binary(pwn::reg::hklm(), sub_key, reg_sz, Seed) == ERROR_SUCCESS )
            pwn::utils::hexdump(Seed);
    }
```
