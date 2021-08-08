#pragma once

#define __STR(x) #x
#define STR(x) __STR(x)
#define __WIDE(x) L#x
#define WIDECHAR(x) __WIDE(x)
#define __WIDE2(x) L##x
#define WIDECHAR2(x) __WIDE2(x)
#define CONCAT(x, y) x##y

#define __PWNLIB_NAME__              WIDECHAR(PROGNAME)
#define __PWNLIB_VERSION_MAJOR__     PWN_VERSION_MAJOR
#define __PWNLIB_VERSION_MINOR__     PWN_VERSION_MINOR
#define __PWNLIB_VERSION__	         WIDECHAR(PWN_VERSION_STR)

#if defined(__linux__)
#define __PWNLIB_LINUX_BUILD__
#else
#define __PWNLIB_WINDOWS_BUILD__ 10
#endif



#ifndef __x86_64__
#define __x86_64__
#endif


