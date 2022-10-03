#pragma once

#define WIN32_LEAN_AND_MEAN // Exclude rarely-used stuff from Windows headers
#define UMDF_USING_NTSTATUS

// Windows Header Files
#pragma warning(push)
#pragma warning(disable : 4005) // Disable macro re-definition warnings

// clang-format off
#include <phnt_windows.h>
#include <phnt.h>
// clang-format on

#pragma warning(pop)


#ifndef UNREFERENCED_PARAMETER
#define UNREFERENCED_PARAMETER(x)                                                                                      \
    {                                                                                                                  \
        (void)x;                                                                                                       \
    }
#endif // UNREFERENCED_PARAMETER

#ifndef UnusedParameter
#define UnusedParameter UNREFERENCED_PARAMETER
#endif // UnusedParameter
