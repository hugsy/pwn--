#include "alpc.hpp"

#include "log.hpp"
using namespace pwn::log;

#include "utils.hpp"


//
// ALPC Messages
//


pwn::windowsdows::alpc::Message::Message(const std::vector<BYTE>& data) : m_Data(data), m_AlpcRawMessage(nullptr)
{
    m_PortMessage.u1.s1.DataLength  = m_Data.size() & USHRT_MAX;
    m_PortMessage.u1.s1.TotalLength = Size() & USHRT_MAX;
}


pwn::windowsdows::alpc::Message::Message(const PBYTE lpRawData, DWORD dwRawDataLength) : m_AlpcRawMessage(nullptr)
{
    //
    // copy the header
    //
    ::RtlCopyMemory(&m_PortMessage, lpRawData, sizeof(PORT_MESSAGE));

    //
    // parse the body as vector of bytes
    //
    SIZE_T data_size = dwRawDataLength - sizeof(PORT_MESSAGE);
    m_Data.resize(data_size, 0);
    ::RtlCopyMemory(m_Data.data(), lpRawData + sizeof(PORT_MESSAGE), data_size);
}


pwn::windowsdows::alpc::Message::~Message()
{
    dbg(L"alpc::message - destroying\n");
    if ( m_AlpcRawMessage )
    {
        ::HeapFree(::GetProcessHeap(), 0, m_AlpcRawMessage);
        m_AlpcRawMessage = nullptr;
    }
}


PPORT_MESSAGE
pwn::windowsdows::alpc::Message::Get()
{
    if ( m_AlpcRawMessage )
    {
        ::HeapFree(::GetProcessHeap(), 0, m_AlpcRawMessage);
        m_AlpcRawMessage = nullptr;
    }

    m_AlpcRawMessage = (PPORT_MESSAGE)::HeapAlloc(::GetProcessHeap(), HEAP_ZERO_MEMORY, Size());
    if ( !m_AlpcRawMessage )
        return nullptr;


    //
    // copy header
    //
    ::RtlCopyMemory(m_AlpcRawMessage, &m_PortMessage, sizeof(PORT_MESSAGE));
    m_AlpcRawMessage->u1.s1.DataLength  = m_Data.size() & USHRT_MAX;
    m_AlpcRawMessage->u1.s1.TotalLength = Size() & USHRT_MAX;


    //
    // copy body
    //
    ::RtlCopyMemory((PBYTE)m_AlpcRawMessage + sizeof(PORT_MESSAGE), m_Data.data(), m_Data.size());

    dbg(L"alpc::message - built alpc message %p\n", m_AlpcRawMessage);

    return (PPORT_MESSAGE)m_AlpcRawMessage;
}


SIZE_T
pwn::windowsdows::alpc::Message::Size() const
{
    return sizeof(PORT_MESSAGE) + m_Data.size();
}

PWNAPI std::vector<BYTE>
pwn::windowsdows::alpc::Message::Data() const
{
    return m_Data;
}


//
// ALPC Base class
//

pwn::windowsdows::alpc::Base::Base(const std::wstring& PortName) :
    m_PortName(PortName),
    m_AlpcSocketHandle(INVALID_HANDLE_VALUE)
{
    if ( !pwn::utils::startswith(PortName, L"\\") )
        throw std::exception("invalid port name");
}


pwn::windowsdows::alpc::Base::~Base()
{
    if ( m_AlpcSocketHandle != INVALID_HANDLE_VALUE )
    {
        if ( !close() )
            err(L"an error occured while closing the handle\n");
    }
}


_Success_(return )
BOOL
pwn::windowsdows::alpc::Base::close()
{
    dbg(L"alpc::base - closing handle %p\n", m_AlpcSocketHandle);
    BOOL bRes = NT_SUCCESS(::NtAlpcDisconnectPort(m_AlpcSocketHandle, 0));
    if ( bRes )
        m_AlpcSocketHandle = INVALID_HANDLE_VALUE;
    return bRes;
}


pwn::windowsdows::alpc::Message
pwn::windowsdows::alpc::Base::send_and_receive(_In_ HANDLE hSocket, _In_ pwn::windowsdows::alpc::Message& MsgIn)
{
    DWORD dwMsgOutLen = 2048;
    auto lpRawMsgOut  = std::make_unique<BYTE[]>(dwMsgOutLen);

    NTSTATUS Status = ::NtAlpcSendWaitReceivePort(
        hSocket,
        0,
        MsgIn.Get(),
        nullptr,
        (PPORT_MESSAGE)lpRawMsgOut.get(),
        &dwMsgOutLen,
        nullptr,
        nullptr);
    if ( NT_SUCCESS(Status) )
    {
        pwn::windowsdows::alpc::Message MsgOut(lpRawMsgOut.get(), dwMsgOutLen);
        return MsgOut;
    }

    throw std::exception("NtAlpcSendWaitReceivePort() failed");
}


pwn::windowsdows::alpc::Message
pwn::windowsdows::alpc::Base::send_and_receive(_In_ HANDLE hSocket, _In_ const std::vector<BYTE>& messageData)
{
    Message MsgIn(messageData);
    return send_and_receive(hSocket, MsgIn);
}


HANDLE
pwn::windowsdows::alpc::Base::SocketHandle()
{
    return m_AlpcSocketHandle;
}


std::wstring
pwn::windowsdows::alpc::Base::PortName()
{
    return m_PortName;
}


//
// ALPC server
//


pwn::windowsdows::alpc::Server::Server(const std::wstring& PortName) : Base(PortName)
{
    NTSTATUS Status;

    UNICODE_STRING AlpcPortName;
    ::RtlInitUnicodeString(&AlpcPortName, m_PortName.c_str());

    OBJECT_ATTRIBUTES ObjectAttributes = {0};
    InitializeObjectAttributes(&ObjectAttributes, &AlpcPortName, 0, 0, 0);

    ALPC_PORT_ATTRIBUTES PortAttributes = {0};
    PortAttributes.MaxMessageLength     = ALPC_PORT_MAXIMUM_MESSAGE_LENGTH;

    Status = ::NtAlpcCreatePort(&m_AlpcSocketHandle, &ObjectAttributes, &PortAttributes);
    if ( !NT_SUCCESS(Status) )
    {
        ntperror(L"NtAlpcCreatePort", Status);
        throw std::exception("critical error in constructor");
    }

    dbg(L"alpc::server - got handle %p for port '%s'\n", m_AlpcSocketHandle, m_PortName.c_str());
}


pwn::windowsdows::alpc::Server::~Server()
{
    dbg(L"alpc::server - closing server...\n");
}


/*++
Description:
    Wait an accept a new ALPC connection.

Arguments:
    - hAlpcServerSocket is a handle to the alpc server socket

Return:
    A client socket handle
--*/
_Success_(return )
BOOL
pwn::windowsdows::alpc::Server::accept(_Out_ PHANDLE NewClientHandle)
{
    auto hAlpcClientSocket = INVALID_HANDLE_VALUE;

    Message ConnectionRequestMsg;

    //
    // wait for initial request
    //
    DWORD OriginalMsgSize = ConnectionRequestMsg.Size() & MAXDWORD;
    NTSTATUS Status       = ::NtAlpcSendWaitReceivePort(
        m_AlpcSocketHandle,
        0,
        nullptr,
        nullptr,
        ConnectionRequestMsg.Get(), /* ReceiveMessage */
        &OriginalMsgSize,           /* BufferLength */
        nullptr,
        nullptr);

    if ( NT_SUCCESS(Status) )
    {
        pwn::utils::hexdump((PBYTE)&ConnectionRequestMsg.m_PortMessage, OriginalMsgSize);
        //
        // If the message was of valid type (i.e. request), we can accept the connection
        //
        if ( ConnectionRequestMsg.m_PortMessage.MessageId == LPC_CONNECTION_REQUEST )
        {
            Status = ::NtAlpcAcceptConnectPort(
                &hAlpcClientSocket,
                m_AlpcSocketHandle,
                0,
                nullptr,
                nullptr,
                nullptr,
                ConnectionRequestMsg.Get(),
                nullptr,
                TRUE);

            if ( !NT_SUCCESS(Status) )
            {
                ntperror(L"NtAlpcAcceptConnectPort()", Status);
                hAlpcClientSocket = INVALID_HANDLE_VALUE;
            }

            *NewClientHandle = hAlpcClientSocket;
        }
        else
        {
            err(L"Unexpected message type received: %d\n", ConnectionRequestMsg.m_PortMessage.MessageId);
        }
    }
    else
        ntperror(L"NtAlpcSendWaitReceivePort()", Status);

    return hAlpcClientSocket != INVALID_HANDLE_VALUE;
}


//
// ALPC client
//

pwn::windowsdows::alpc::Client::Client(const std::wstring& PortName) : Base(PortName)
{
    if ( !reconnect() )
        throw std::exception("failed to establish connection");
}


pwn::windowsdows::alpc::Client::~Client()
{
    dbg(L"alpc::client - closing client\n");
}


_Success_(return )
BOOL
pwn::windowsdows::alpc::Client::reconnect()
{
    UNICODE_STRING AlpcPortName;
    ::RtlInitUnicodeString(&AlpcPortName, m_PortName.c_str());

    NTSTATUS Status = ::NtAlpcConnectPort(
        &m_AlpcSocketHandle,
        &AlpcPortName,
        nullptr,
        nullptr,
        0,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr);
    if ( !NT_SUCCESS(Status) )
    {
        ntperror(L"NtAlpcConnectPort()", Status);
        return FALSE;
    }

    dbg(L"alpc::client - port connected\n");
    return TRUE;
}


pwn::windowsdows::alpc::Message
pwn::windowsdows::alpc::Client::sr(_In_ const std::vector<BYTE>& messageData)
{
    return send_and_receive(m_AlpcSocketHandle, messageData);
}

pwn::windowsdows::alpc::Message
pwn::windowsdows::alpc::Client::sr(_In_ Message& message)
{
    return send_and_receive(m_AlpcSocketHandle, message);
}
