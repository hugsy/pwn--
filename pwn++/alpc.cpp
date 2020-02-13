#include "alpc.h"

#include "log.h"
using namespace pwn::log;


PPORT_MESSAGE pwn::windows::alpc::create_alpc_message(_In_ const std::vector<BYTE>& data)
{
    LPBYTE lpMsg = (LPBYTE)::HeapAlloc(::GetProcessHeap(), HEAP_ZERO_MEMORY, data.size() + sizeof(PORT_MESSAGE));
    if ( !lpMsg )
        return nullptr;

    //
    // copy header
    //
    auto p = (PPORT_MESSAGE)lpMsg;
    p->u1.s1.DataLength = (data.size() & 0xffff);
    p->u1.s1.TotalLength = p->u1.s1.DataLength + sizeof(PORT_MESSAGE);


    //
    // copy body
    //
    ::RtlCopyMemory(lpMsg + sizeof(PORT_MESSAGE), data.data(), data.size());
    return p;
}


BOOL pwn::windows::alpc::delete_alpc_message(_In_ PPORT_MESSAGE AlpcMessage)
{
    return ::HeapFree(::GetProcessHeap(), 0, AlpcMessage);
}


HANDLE pwn::windows::alpc::client::connect(_In_ const wchar_t* lpwszServerName)
{
    NTSTATUS Status;
    HANDLE hAlpcSocket = INVALID_HANDLE_VALUE;
    UNICODE_STRING AlpcPortName;
    
    ::RtlInitUnicodeString(&AlpcPortName, lpwszServerName);
    
    Status = ::NtAlpcConnectPort(&hAlpcSocket, &AlpcPortName, NULL, nullptr, 0, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr);
    if ( !NT_SUCCESS(Status) )
    {
        err(L"NtAlpcConnectPort() failed with 0x%x\n", Status);
        return INVALID_HANDLE_VALUE;
    }

    return hAlpcSocket;
}



std::vector<BYTE> pwn::windows::alpc::client::send_and_receive(_In_ HANDLE hSocket, _In_opt_ const std::vector<BYTE> message)
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
            err(L"NtAlpcSendWaitReceivePort() failed with 0x%x\n", Status);

        delete_alpc_message(MsgIn);
    }

	return received_data;
}


BOOL pwn::windows::alpc::client::close(_In_ HANDLE hSocket)
{
    return NT_SUCCESS(::NtAlpcDisconnectPort(hSocket, 0));
}


HANDLE pwn::windows::alpc::server::listen(_In_ const std::wstring& lpwszServerName)
{
    return INVALID_HANDLE_VALUE;
}


