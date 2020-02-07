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


#include <array>
#include <vector>
#include <string>
#include <memory>


#if defined(__WIN10__)
#pragma message L"Compiling " __PWNLIB__ " for Windows 10 x64"
#elif defined(__WIN81__)
#pragma message "Compiling " __PWNLIB__ " for Windows 8.1 x64"
#elif defined(__WIN8__)
#pragma message "Compiling " __PWNLIB__ " for Windows 8 x64"
#elif defined(__WIN7__)
#pragma message "Compiling " __PWNLIB__ " for Windows 7 x64"
#endif