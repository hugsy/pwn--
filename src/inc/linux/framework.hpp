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

#include <unistd.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdint.h>

#ifndef MAX_PATH
#define MAX_PATH 260
#endif // MAX_PATH

#ifndef UnusedParameter
#define UnusedParameter (void)
#endif // UnusedParameter
