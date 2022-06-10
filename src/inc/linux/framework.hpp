#pragma once


//
// Windows SAL compat stuff
//
#define _In_
#define _In_opt_
#define _Out_
#define _Out_opt_
#define _Inout_
#define _Inout_opt_

#define _Success_(c)

#include <dlfcn.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#ifndef MAX_PATH
#define MAX_PATH 260
#endif // MAX_PATH

#ifndef UnusedParameter
#define UnusedParameter(x) (void)(x)
#endif // UnusedParameter
