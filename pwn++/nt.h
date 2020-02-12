#pragma once

/*++

Various NT related structures and signatures from various resources

Sources:
 - processhacker
 - reactos
 - geoffchappell
 - cuckoobox
--*/

#include <windows.h>
#include <winternl.h>

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



/*++

https://github.com/hugsy/ldos-ionescu007/blob/master/src/ldos/alpc.h

--*/

#define ALPC_MSGFLG_SYNC_REQUEST 0x20000 


typedef struct _QUAD
{
	double DoNotUseThisField;
} QUAD, *PQUAD, UQUAD, *PUQUAD;

typedef struct _PORT_MESSAGE
{
	union
	{
		struct
		{
			SHORT DataLength;
			SHORT TotalLength;
		} s1;
		ULONG Length;
	} u1;
	union
	{
		struct
		{
			SHORT Type;
			SHORT DataInfoOffset;
		} s2;
		ULONG ZeroInit;
	} u2;
	union
	{
		CLIENT_ID ClientId;
		QUAD DoNotUseThisField;
	};
	ULONG MessageId;
	union
	{
		SIZE_T ClientViewSize; // only valid for LPC_CONNECTION_REQUEST messages
		ULONG CallbackId; // only valid for LPC_REQUEST messages
	};
} PORT_MESSAGE, * PPORT_MESSAGE;

typedef struct _ALPC_MESSAGE_ATTRIBUTES
{
	ULONG AllocatedAttributes;
	ULONG ValidAttributes;
} ALPC_MESSAGE_ATTRIBUTES, * PALPC_MESSAGE_ATTRIBUTES;

typedef struct _ALPC_PORT_ATTRIBUTES
{
	ULONG Flags;
	SECURITY_QUALITY_OF_SERVICE SecurityQos;
	SIZE_T MaxMessageLength;
	SIZE_T MemoryBandwidth;
	SIZE_T MaxPoolUsage;
	SIZE_T MaxSectionSize;
	SIZE_T MaxViewSize;
	SIZE_T MaxTotalSectionSize;
	ULONG DupObjectTypes;
#ifdef _M_X64
	ULONG Reserved;
#endif
} ALPC_PORT_ATTRIBUTES, * PALPC_PORT_ATTRIBUTES;

NTSYSCALLAPI
NTSTATUS
NTAPI
NtAlpcConnectPort(
	__out PHANDLE PortHandle,
	__in PUNICODE_STRING PortName,
	__in POBJECT_ATTRIBUTES ObjectAttributes,
	__in_opt PALPC_PORT_ATTRIBUTES PortAttributes,
	__in ULONG Flags,
	__in_opt PSID RequiredServerSid,
	__inout PPORT_MESSAGE ConnectionMessage,
	__inout_opt PULONG BufferLength,
	__inout_opt PALPC_MESSAGE_ATTRIBUTES OutMessageAttributes,
	__inout_opt PALPC_MESSAGE_ATTRIBUTES InMessageAttributes,
	__in_opt PLARGE_INTEGER Timeout
);

NTSYSCALLAPI
NTSTATUS
NTAPI
NtAlpcSendWaitReceivePort(
	__in HANDLE PortHandle,
	__in ULONG Flags,
	__in_opt PPORT_MESSAGE SendMessage_,
	__in_opt PALPC_MESSAGE_ATTRIBUTES SendMessageAttributes,
	__inout_opt PPORT_MESSAGE ReceiveMessage,
	__inout_opt PULONG BufferLength,
	__inout_opt PALPC_MESSAGE_ATTRIBUTES ReceiveMessageAttributes,
	__in_opt PLARGE_INTEGER Timeout
);