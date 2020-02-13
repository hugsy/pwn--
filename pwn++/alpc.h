#pragma once

#include "common.h"
#include "nt.h"




/********************************************************************************
 *
 * ALPC internals
 *
 * ref:
 * https://github.com/hugsy/ldos-ionescu007/blob/master/src/ldos/alpc.h
 * processhacker
 ********************************************************************************/

#define ALPC_MSGFLG_SYNC_REQUEST 0x20000 


typedef struct _QUAD
{
	double DoNotUseThisField;
} QUAD, * PQUAD, UQUAD, * PUQUAD;

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


extern "C"
NTSYSCALLAPI
NTSTATUS
NTAPI
NtAlpcConnectPort(
	__out PHANDLE PortHandle,
	__in PUNICODE_STRING PortName,
	__in_opt POBJECT_ATTRIBUTES ObjectAttributes,
	__in_opt PALPC_PORT_ATTRIBUTES PortAttributes,
	__in ULONG Flags,
	__in_opt PSID RequiredServerSid,
	__inout PPORT_MESSAGE ConnectionMessage,
	__inout_opt PULONG BufferLength,
	__inout_opt PALPC_MESSAGE_ATTRIBUTES OutMessageAttributes,
	__inout_opt PALPC_MESSAGE_ATTRIBUTES InMessageAttributes,
	__in_opt PLARGE_INTEGER Timeout
);


extern "C"
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


extern "C"
NTSYSCALLAPI
NTSTATUS
NTAPI
NtAlpcDisconnectPort(
	_In_ HANDLE PortHandle,
	_In_ ULONG Flags
);


namespace pwn::windows::alpc
{
	PWNAPI PPORT_MESSAGE create_alpc_message(_In_ const std::vector<BYTE>& data);
	PWNAPI BOOL delete_alpc_message(_In_ PPORT_MESSAGE AlpcMessage);


	namespace client
	{
		PWNAPI HANDLE connect(_In_ const wchar_t* lpwszServerName);
		PWNAPI std::vector<BYTE> send_and_receive(_In_ HANDLE hSocket, _In_opt_ const std::vector<BYTE>message);
		PWNAPI BOOL close(_In_ HANDLE hSocket);
	}


	namespace server
	{
		PWNAPI HANDLE listen(_In_ const std::wstring& lpwszServerName);
	}
}
