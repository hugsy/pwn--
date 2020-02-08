#include "pwn.h"


const wchar_t* pwn::version()
{
	return __PWNLIB_VERSION__;
}


const std::tuple<WORD, WORD> pwn::version_info()
{
	const std::tuple<WORD, WORD> out(__PWNLIB_VERSION_MAJOR__, __PWNLIB_VERSION_MINOR__);
	return out;
}