#pragma once

#include "framework.h"
#include "constants.h"


#ifndef PWNAPI
#define PWNAPI __declspec(dllexport)
#endif


#ifndef __countof
#define __countof(x) (sizeof(x)/x[0])
#endif 

typedef DWORD64 QWORD;


#include <stdint.h>

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;

typedef int8_t  i8;
typedef int16_t i16;
typedef int32_t i32;
typedef int64_t i64;


#ifndef _PWN_LOG_NO_COLOR
#define PWN_LOG_USE_COLOR
#endif 

#include <array>
#include <vector>
#include <string>
#include <memory>
#include <exception>


template< typename modHandleType, typename procNameType >
auto LoadModAndProcOrFail(modHandleType modHandle, procNameType procName) {
    auto address = ::GetProcAddress(modHandle, procName);
    if (!address) 
        throw std::exception{ (std::string{"Error importing: "} + (std::string{procName})).c_str() };
    return address;
}



#define IMPORT_EXTERNAL_FUNCTION( DLLFILE, FUNCNAME, RETTYPE, ... )                                                          \
   typedef RETTYPE( WINAPI* CONCAT( t_, FUNCNAME ) )( __VA_ARGS__ );                                                         \
   template< typename... Ts >                                                                                                \
   auto FUNCNAME( Ts... ts ) {                                                                                               \
      const static CONCAT( t_, FUNCNAME ) func =                                                                             \
       (CONCAT( t_, FUNCNAME )) LoadModAndProcOrFail( ( LoadLibraryW( DLLFILE ), GetModuleHandleW( DLLFILE ) ), #FUNCNAME ); \
      return func( std::forward< Ts >( ts )... );                                                                            \
   } 


//
// Usage example below with ntdll!ZwCreateEnclave(https://docs.microsoft.com/en-us/windows/win32/api/enclaveapi/nf-enclaveapi-createenclave)
// The comment allows to be picked up by intellisense.
// 
// 
// /*++
// Creates a new uninitialized enclave. An enclave is an isolated region of code and data within the address space for an application. 
// Only code that runs within the enclave can access data within the same enclave.
// --*/
// IMPORT_EXTERNAL_FUNCTION( \
//     L"ntdll.dll", \
//     ZwCreateEnclave, \
//     NTSTATUS, \
//     HANDLE  hProcess, \
//     LPVOID  lpAddress, \
//     ULONGLONG ZeroBits, \
//     SIZE_T  dwSize, \
//     SIZE_T  dwInitialCommitment, \
//     DWORD   flEnclaveType, \
//     LPCVOID lpEnclaveInformation, \
//     DWORD   dwInfoLength, \
//     LPDWORD lpEnclaveError \
// );
// 

