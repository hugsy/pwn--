#include "alpc.h"

#include "log.h"
using namespace pwn::log;


_Success_(return != nullptr)
PPORT_MESSAGE pwn::windows::alpc::create_alpc_message(_In_ const std::vector<BYTE>& data)
{
	LPBYTE lpMsg = (LPBYTE)::HeapAlloc(::GetProcessHeap(), HEAP_ZERO_MEMORY, data.size() + sizeof(PORT_MESSAGE));
	if ( !lpMsg )
		return nullptr;

	//
	// copy header
	//
	auto p = (PPORT_MESSAGE)lpMsg;
	p->u1.s1.DataLength = (data.size() & USHRT_MAX);
	p->u1.s1.TotalLength = p->u1.s1.DataLength + sizeof(PORT_MESSAGE);


	//
	// copy body
	//
	::RtlCopyMemory(lpMsg + sizeof(PORT_MESSAGE), data.data(), data.size());
	return p;
}


_Success_(return)
BOOL pwn::windows::alpc::delete_alpc_message(_In_ PPORT_MESSAGE AlpcMessage)
{
	return ::HeapFree(::GetProcessHeap(), 0, AlpcMessage);
}


std::vector<BYTE> pwn::windows::alpc::send_and_receive(_In_ HANDLE hSocket, _In_opt_ const std::vector<BYTE> message)
{
	std::vector<BYTE> received_data;
	DWORD dwMsgOutLen = 2048;

	auto MsgIn = create_alpc_message(message);
	if ( MsgIn )
	{
		auto lpRawMsgOut = std::make_unique<BYTE[]>(dwMsgOutLen);
		auto MsgOut = (PPORT_MESSAGE)lpRawMsgOut.get();

		NTSTATUS Status = ::NtAlpcSendWaitReceivePort(hSocket, 0, MsgIn, nullptr, MsgOut, &dwMsgOutLen, nullptr, nullptr);
		if ( NT_SUCCESS(Status) )
		{
			auto DataReceived = &lpRawMsgOut[sizeof(PPORT_MESSAGE)];
			auto data_size = MsgOut->u1.s1.DataLength;
			received_data.reserve(data_size);
			std::copy(DataReceived, DataReceived + data_size, std::back_inserter(received_data));
		}
		else
			ntperror(L"NtAlpcSendWaitReceivePort()", Status);

		delete_alpc_message(MsgIn);
	}

	return received_data;
}


_Success_(return)
BOOL pwn::windows::alpc::close(_In_ HANDLE hSocket)
{
	return NT_SUCCESS(::NtAlpcDisconnectPort(hSocket, 0));
}



_Success_(return != INVALID_HANDLE_VALUE)
HANDLE pwn::windows::alpc::client::connect(_In_ const wchar_t* lpwszServerName)
{
	NTSTATUS Status;
	HANDLE hAlpcSocket = INVALID_HANDLE_VALUE;
	UNICODE_STRING AlpcPortName;

	::RtlInitUnicodeString(&AlpcPortName, lpwszServerName);

	Status = ::NtAlpcConnectPort(&hAlpcSocket, &AlpcPortName, nullptr, nullptr, 0, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr);
	if ( !NT_SUCCESS(Status) )
	{
		ntperror(L"NtAlpcConnectPort()", Status);
		return INVALID_HANDLE_VALUE;
	}

	return hAlpcSocket;
}


_Success_(return != INVALID_HANDLE_VALUE)
HANDLE pwn::windows::alpc::server::listen(_In_ const wchar_t* lpwszServerName)
{
	NTSTATUS Status;
	HANDLE hAlpcSocket = INVALID_HANDLE_VALUE;
	UNICODE_STRING AlpcPortName;
	OBJECT_ATTRIBUTES ObjectAttributes = { 0 };
	ALPC_PORT_ATTRIBUTES PortAttributes = { 0 };

	::RtlInitUnicodeString(&AlpcPortName, lpwszServerName);

	InitializeObjectAttributes(&ObjectAttributes, &AlpcPortName, 0, 0, 0);

	PortAttributes.MaxMessageLength = ALPC_PORT_MAXIMUM_MESSAGE_LENGTH;
	Status = ::NtAlpcCreatePort(&hAlpcSocket, &ObjectAttributes, &PortAttributes);
	if ( !NT_SUCCESS(Status) ) 
	{
		ntperror(L"NtAlpcCreatePort()", Status);
		return INVALID_HANDLE_VALUE;
	}

	return hAlpcSocket;
}


/*++
Description:
	Wait an accept a new ALPC connection.

Arguments:
	- hAlpcServerSocket is a handle to the alpc server socket

Return:
	A client socket handle
--*/
_Success_(return != INVALID_HANDLE_VALUE)
HANDLE pwn::windows::alpc::server::accept(_In_ HANDLE hAlpcServerSocket)
{
	auto hAlpcClientSocket = INVALID_HANDLE_VALUE;
	
	auto ConnectionRequestMsg = create_alpc_message({});
	if ( ConnectionRequestMsg )
	{
		DWORD ConnectionRequestMsgLen = 0;

		//
		// wait for initial request
		// 
		NTSTATUS Status = ::NtAlpcSendWaitReceivePort(
			hAlpcServerSocket, 
			0, 
			nullptr, 
			nullptr, 
			ConnectionRequestMsg, 
			&ConnectionRequestMsgLen, 
			nullptr, 
			nullptr
		);

		if ( NT_SUCCESS(Status) )
		{
			//
			// If the message was of valid type (i.e. request), we can accept the connection
			//
			if ( ConnectionRequestMsg->MessageId == LPC_CONNECTION_REQUEST )
			{
				Status = ::NtAlpcAcceptConnectPort(
					&hAlpcClientSocket, 
					hAlpcServerSocket, 
					0, 
					nullptr, 
					nullptr, 
					nullptr, 
					ConnectionRequestMsg, 
					nullptr, 
					TRUE
				);

				if ( !NT_SUCCESS(Status) )
				{
					ntperror(L"NtAlpcAcceptConnectPort()", Status);
					hAlpcClientSocket = INVALID_HANDLE_VALUE;
				}
			}
			else
				err(L"Unexpected message type received: %d\n", ConnectionRequestMsg->MessageId);
		}
		else
			ntperror(L"NtAlpcSendWaitReceivePort()", Status);

		delete_alpc_message(ConnectionRequestMsg);
	}

	return hAlpcClientSocket;
}

