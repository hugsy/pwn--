#include "pwn.hpp"


PWNAPI struct pwn::globals_t pwn::globals;

auto
pwn::version() -> const wchar_t*
{
    return __PWNLIB_VERSION__;
}


auto
pwn::version_info() -> const std::tuple<u16, u16>
{
    const std::tuple<u16, u16> out(__PWNLIB_VERSION_MAJOR__, __PWNLIB_VERSION_MINOR__);
    return out;
}
