#pragma once

#define WIN32_LEAN_AND_MEAN             // Exclude rarely-used stuff from Windows headers
#define UMDF_USING_NTSTATUS

// Windows Header Files
#include <windows.h>
#include <winternl.h>
#include <sal.h>
#include <ntstatus.h>