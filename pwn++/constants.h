#pragma once

#define __STR(x) #x
#define STR(x) __STR(x)
#define __WIDE(x) L#x
#define WIDECHAR(x) __WIDE(x)
#define __WIDE2(x) L##x
#define WIDECHAR2(x) __WIDE2(x)

#define __PWNLIB_NAME__              L"PwnLib"
#define __PWNLIB_VERSION_MAJOR__     0
#define __PWNLIB_VERSION_MINOR__     1
#define __PWNLIB_VERSION__	         L"v" WIDECHAR(__PWNLIB_VERSION_MAJOR__) L"." WIDECHAR(__PWNLIB_VERSION_MINOR__)


#ifndef __WIN10__
#define __WIN10__       TRUE
#endif


#ifndef __x86_64__
#define __x86_64__      TRUE
#endif


