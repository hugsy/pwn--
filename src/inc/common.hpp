#pragma once

#include "constants.hpp"
#include "pwn_export.hpp"

#define __STR(x) #x
#define STR(x) __STR(x)
#define __WIDE(x) L#x
#define WIDECHAR(x) __WIDE(x)
#define __WIDE2(x) L##x
#define WIDECHAR2(x) __WIDE2(x)
#define CONCAT(x, y) (x##y)


#if defined(__PWNLIB_WINDOWS_BUILD__)
#include "win32/framework.hpp"

#elif defined(__PWNLIB_LINUX_BUILD__)
#include "linux/framework.hpp"
#endif


#ifndef __countof
#define __countof(x) (sizeof(x) / sizeof(x[0]))
#endif


#ifndef MIN
#define MIN(x, y) (((size_t)x) < ((size_t)y))
#endif


using u8  = uint8_t;
using u16 = uint16_t;
using u32 = uint32_t;
using u64 = uint64_t;

using uptr  = uintptr_t;
using usize = size_t;

using i8  = int8_t;
using i16 = int16_t;
using i32 = int32_t;
using i64 = int64_t;

#ifdef __PWNLIB_WINDOWS_BUILD__

// todo: port to linux too
template<typename M, typename P>
auto
LoadModuleOrThrow(M hMod, P lpszProcName)
{
    auto address = ::GetProcAddress(hMod, lpszProcName);
    if ( !address )
    {
        throw std::exception((std::string("Error importing: ") + std::string(lpszProcName)).c_str());
    }
    return address;
}


// todo: samesies
#define IMPORT_EXTERNAL_FUNCTION(DLLFILE, FUNCNAME, RETTYPE, ...)                                                      \
    typedef RETTYPE(WINAPI* CONCAT(t_, FUNCNAME))(__VA_ARGS__);                                                        \
    template<typename... Ts>                                                                                           \
    auto FUNCNAME(Ts... ts)                                                                                            \
    {                                                                                                                  \
        const static CONCAT(t_, FUNCNAME) func =                                                                       \
            (CONCAT(t_, FUNCNAME))LoadModuleOrThrow((LoadLibraryW(DLLFILE), GetModuleHandleW(DLLFILE)), #FUNCNAME);    \
        return func(std::forward<Ts>(ts)...);                                                                          \
    }

#endif
