//#include <windows.h>

#include <sdkddkver.h>

#define __STR(x) #x
#define STR(x) __STR(x)


#pragma message("Compiling " __FILE__)
#pragma message("Last modified on " __TIMESTAMP__)
#pragma message("NTDDI_WIN10_CO = " STR(NTDDI_WIN10_CO))
#pragma message("NTDDI_VERSION < NTDDI_WIN10_CO = " STR(NTDDI_VERSION) " < " STR(NTDDI_WIN10_CO))
