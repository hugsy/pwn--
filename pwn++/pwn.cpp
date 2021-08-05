#include "pwn.h"



namespace pwn
{



struct pwn::globals_t globals;

auto
pwn::version() -> const wchar_t *
{
    return __PWNLIB_VERSION__;
}


auto
pwn::version_info() -> const std::tuple<WORD, WORD>
{
    const std::tuple<WORD, WORD> out(__PWNLIB_VERSION_MAJOR__, __PWNLIB_VERSION_MINOR__);
    return out;
}

}


