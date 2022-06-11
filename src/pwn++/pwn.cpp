#include "pwn.hpp"


PWNAPI struct pwn::globals_t pwn::globals;

auto
pwn::banner() -> const wchar_t*
{
    return PWN_LIBRARY_NAME L" v" PWN_LIBRARY_VERSION L" - " PWN_LIBRARY_VERSION_RELEASE;
}

auto
pwn::version() -> const wchar_t*
{
    return PWN_LIBRARY_VERSION;
}


auto
pwn::version_info() -> const std::tuple<u16, u16>
{
    const std::tuple<u16, u16> out(PWN_LIBRARY_VERSION_MAJOR, PWN_LIBRARY_VERSION_MINOR);
    return out;
}
