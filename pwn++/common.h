#pragma once

#include "framework.h"
#include "constants.h"


#ifndef PWNAPI
#define PWNAPI __declspec(dllexport)
#endif


#ifndef __countof
#define __countof(x) (sizeof(x)/sizeof(x[0]))
#endif 

using QWORD = DWORD64;


#include <cstdint>

using u8 = uint8_t;
using u16 = int16_t;
using u32 = uint32_t;
using u64 = uint64_t;

using i8 = int8_t;
using i16 = int16_t;
using i32 = int32_t;
using i64 = int64_t;


#ifndef PWN_LOG_NO_COLOR
#define PWN_LOG_USE_COLOR
#endif // !PWN_LOG_NO_COLOR */


// uncomment to disable to the integration with capstone
// #define PWN_NO_ASSEMBLER
// uncomment to disable to the integration with keystone
// #define PWN_NO_DISASSEMBLER


// comment to disable to backdoor
// #define PWN_AUTOSTART_BACKDOOR
#undef PWN_AUTOSTART_BACKDOOR



#include <array>
#include <vector>
#include <string>
#include <memory>
#include <exception>


template<typename M, typename P>
auto LoadModuleOrThrow(M hMod, P lpszProcName) 
{
    auto address = ::GetProcAddress(hMod, lpszProcName);
    if (!address)
    {
        throw std::exception(  std::string("Error importing: ") << std::string(lpszProcName).c_str() );
    }
    return address;
}



#define IMPORT_EXTERNAL_FUNCTION( DLLFILE, FUNCNAME, RETTYPE, ... )                                                          \
   typedef RETTYPE( WINAPI* CONCAT( t_, FUNCNAME ) )( __VA_ARGS__ );                                                         \
   template< typename... Ts >                                                                                                \
   auto FUNCNAME( Ts... ts ) {                                                                                               \
      const static CONCAT( t_, FUNCNAME ) func =                                                                             \
        (CONCAT( t_, FUNCNAME )) LoadModuleOrThrow( ( LoadLibraryW( DLLFILE ), GetModuleHandleW( DLLFILE ) ), #FUNCNAME );   \
      return func( std::forward< Ts >( ts )... );                                                                            \
   } 
