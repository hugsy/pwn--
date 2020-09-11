#pragma once

/*++

Various NT related structures and signatures from various resources

Sources:
 - https://github.com/processhacker/phnt
 - https://github.com/reactos/reactos
 - https://www.geoffchappell.com/
 - https://www.nirsoft.net/
 - https://www.vergiliusproject.com/
--*/



#include <windows.h>
#include <winternl.h>


#pragma comment(lib, "ntdll.lib")



/*++
SYSTEM_INFORMATION_CLASS
https://www.geoffchappell.com/studies/windows/km/ntoskrnl/api/ex/sysinfo/class.htm
https://github.com/processhacker/processhacker/blob/89fe55ce6a25f57e5a72a649c7a17d75b8d60e4c/phnt/include/ntexapi.h#L1250
--*/
#define SystemModuleInformation  (SYSTEM_INFORMATION_CLASS)11
#define SystemHandleInformation (SYSTEM_INFORMATION_CLASS)16
#define SystemExtendedHandleInformation (SYSTEM_INFORMATION_CLASS)64
#define SystemBigPoolInformation (SYSTEM_INFORMATION_CLASS)66
/* EndOf(SYSTEM_INFORMATION_CLASS) */


/*++
THREAD_INFORMATION_CLASS
--*/
#define ThreadNameInformation (THREAD_INFORMATION_CLASS)38
/* EndOf(THREAD_INFORMATION_CLASS) */


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
} RTL_PROCESS_MODULES, *PRTL_PROCESS_MODULES;


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
} SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX, *PSYSTEM_HANDLE_TABLE_ENTRY_INFO_EX;


typedef struct _SYSTEM_HANDLE_INFORMATION_EX
{
	ULONG_PTR NumberOfHandles;
	ULONG_PTR Reserved;
	SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX Handles[1];
} SYSTEM_HANDLE_INFORMATION_EX, *PSYSTEM_HANDLE_INFORMATION_EX;




typedef struct __SYSTEM_HANDLE_TABLE_ENTRY_INFO
{
	USHORT UniqueProcessId;
	USHORT CreatorBackTraceIndex;
	UCHAR ObjectTypeIndex;
	UCHAR HandleAttributes;
	USHORT HandleValue;
	PVOID Object;
	ULONG GrantedAccess;
}
SYSTEM_HANDLE_TABLE_ENTRY_INFO, * PSYSTEM_HANDLE_TABLE_ENTRY_INFO;





typedef struct __SYSTEM_HANDLE_INFORMATION
{
	ULONG NumberOfHandles;
	SYSTEM_HANDLE_TABLE_ENTRY_INFO Handles[ANYSIZE_ARRAY];
}
SYSTEM_HANDLE_INFORMATION, * PSYSTEM_HANDLE_INFORMATION;








/********************************************************************************
 *
 * Process internals (TEB/PEB)
 *
 ********************************************************************************/


typedef struct _RTL_ACTIVATION_CONTEXT_STACK_FRAME
{
	struct _RTL_ACTIVATION_CONTEXT_STACK_FRAME* Previous;
	_ACTIVATION_CONTEXT* ActivationContext;
	ULONG Flags;
} RTL_ACTIVATION_CONTEXT_STACK_FRAME, *PRTL_ACTIVATION_CONTEXT_STACK_FRAME;


typedef struct _ACTIVATION_CONTEXT_STACK
{
	PRTL_ACTIVATION_CONTEXT_STACK_FRAME ActiveFrame;
	LIST_ENTRY FrameListCache;
	ULONG Flags;
	ULONG NextCookieSequenceNumber;
	ULONG StackId;
} ACTIVATION_CONTEXT_STACK, *PACTIVATION_CONTEXT_STACK;


typedef struct _GDI_TEB_BATCH
{
	ULONG Offset;
	ULONG HDC;
	ULONG Buffer[310];
} GDI_TEB_BATCH, * PGDI_TEB_BATCH;


typedef struct _TEB_ACTIVE_FRAME_CONTEXT
{
	ULONG Flags;
	CHAR* FrameName;
} TEB_ACTIVE_FRAME_CONTEXT, *PTEB_ACTIVE_FRAME_CONTEXT;


typedef struct _TEB_ACTIVE_FRAME
{
	ULONG Flags;
	struct _TEB_ACTIVE_FRAME* Previous;
	PTEB_ACTIVE_FRAME_CONTEXT Context;
} TEB_ACTIVE_FRAME, *PTEB_ACTIVE_FRAME;


typedef struct _BIG_POOL_INFO
{
	DWORD64 Address;
	DWORD64 PoolSize;
	DWORD PoolTag;
	char Padding[4];
} BIG_POOL_INFO, * PBIG_POOL_INFO;


#ifndef UNLEN
#define UNLEN 256
#endif // !UNLEN
