#pragma once

/*
Sources:
 - processhacker
 - reactos
 - geoffchappell
 - cuckoobox
*/

#include <windows.h>

#ifndef STATUS_INFO_LENGTH_MISMATCH
#define STATUS_INFO_LENGTH_MISMATCH (NTSTATUS) 0xC0000004
#endif


/*++
SYSTEM_INFORMATION_CLASS
https://www.geoffchappell.com/studies/windows/km/ntoskrnl/api/ex/sysinfo/class.htm
--*/
#define SystemModuleInformation  (SYSTEM_INFORMATION_CLASS)0xb
#define SystemExtendedHandleInformation (SYSTEM_INFORMATION_CLASS)0x40
/* EndOf(SYSTEM_INFORMATION_CLASS) */


typedef struct _RTL_PROCESS_MODULES
{
    ULONG NumberOfModules;
    struct _RTL_PROCESS_MODULE_INFORMATION
    {
        //
        // Structures from Process Hacker source code
        // http://processhacker.sourceforge.net/doc/ntldr_8h_source.html#l00511
        //
        HANDLE Section;
        PVOID MappedBase;
        PVOID ImageBase;
        ULONG ImageSize;
        ULONG Flags;
        USHORT LoadOrderIndex;
        USHORT InitOrderIndex;
        USHORT LoadCount;
        USHORT OffsetToFileName;
        UCHAR FullPathName[256];
    } Modules[1];
} RTL_PROCESS_MODULES;


typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX
{
    PVOID Object;
    ULONG_PTR UniqueProcessId;
    ULONG_PTR HandleValue;
    ULONG GrantedAccess;
    USHORT CreatorBackTraceIndex;
    USHORT ObjectTypeIndex;
    ULONG HandleAttributes;
    ULONG Reserved;
} SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX, * PSYSTEM_HANDLE_TABLE_ENTRY_INFO_EX;

typedef struct _SYSTEM_HANDLE_INFORMATION_EX
{
    ULONG_PTR NumberOfHandles;
    ULONG_PTR Reserved;
    SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX Handles[1];
} SYSTEM_HANDLE_INFORMATION_EX, * PSYSTEM_HANDLE_INFORMATION_EX;

