#pragma once

#define WIN32_LEAN_AND_MEAN             // Exclude rarely-used stuff from Windows headers
#define UMDF_USING_NTSTATUS

// Windows Header Files
#include <windows.h>

#ifndef _WINTERNL_
#include <winternl.h>
#endif

#ifndef __ATTR_SAL
#include <sal.h>
#endif

#ifndef _NTSTATUS_
#include <ntstatus.h>
#endif