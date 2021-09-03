#pragma once


#define __PWNLIB_NAME__              L"pwn++"
#define __PWNLIB_AUTHOR__            L"hugsy"
#define __PWNLIB_LICENSE__           L"MIT"
#define __PWNLIB_VERSION_MAJOR__     0
#define __PWNLIB_VERSION_MINOR__     1
#define __PWNLIB_VERSION__	         L"0.1-dev:003e5e1"
#define __PWNLIB_TARGET_ARCH__       L"AMD64"
#define __PWNLIB_TARGET_OS__         L"Windows"
#define __PWNLIB_TARGET__            L"Windows" L"/" L"AMD64"


#if defined(__linux__)
#define __PWNLIB_LINUX_BUILD__
#else
#define __PWNLIB_WINDOWS_BUILD__ 10
#endif



#ifndef __x86_64__
#define __x86_64__
#endif


/* #undef PWN_LOG_USE_COLOR */
