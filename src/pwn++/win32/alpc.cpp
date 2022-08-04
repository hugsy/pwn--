#include "alpc.hpp"

#include "log.hpp"
using namespace pwn::log;

#include "utils.hpp"

/**
 * ALPC basic implementation
 *
 * Some references:
 * - https://csandker.io/2022/05/24/Offensive-Windows-IPC-3-ALPC.html
 * - https://github.com/bnagy/alpcgo
 */


////////////////////////////////////////////////////////////////////
//
// ALPC Messages
//


pwn::windows::alpc::Message::Message(const std::vector<BYTE>& data) : m_Data(data), m_AlpcRawMessage(nullptr)
{
    m_PortMessage.u1.s1.DataLength  = m_Data.size() & USHRT_MAX;
    m_PortMessage.u1.s1.TotalLength = Size() & USHRT_MAX;
}


pwn::windows::alpc::Message::Message(const PBYTE lpRawData, DWORD dwRawDataLength) : m_AlpcRawMessage(nullptr)
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


pwn::windows::alpc::Message::~Message()
{
    dbg(L"alpc::message - destroying\n");
    if ( m_AlpcRawMessage )
    {
        ::HeapFree(::GetProcessHeap(), 0, m_AlpcRawMessage);
        m_AlpcRawMessage = nullptr;
    }
}


PPORT_MESSAGE
pwn::windows::alpc::Message::Get()
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

    dbg(L"alpc::message - built alpc message {:p}", (void*)m_AlpcRawMessage);

    return (PPORT_MESSAGE)m_AlpcRawMessage;
}


SIZE_T
pwn::windows::alpc::Message::Size() const
{
    return sizeof(PORT_MESSAGE) + m_Data.size();
}

PWNAPI std::vector<BYTE>
pwn::windows::alpc::Message::Data() const
{
    return m_Data;
}


////////////////////////////////////////////////////////////////////
//
// ALPC Base class
//

pwn::windows::alpc::Base::Base(const std::wstring& PortName) :
    m_PortName(PortName),
    m_AlpcSocketHandle(INVALID_HANDLE_VALUE)
{
    if ( !pwn::utils::startswith(PortName, L"\\") )
        throw std::exception("invalid port name");
}


pwn::windows::alpc::Base::~Base()
{
    if ( m_AlpcSocketHandle != INVALID_HANDLE_VALUE )
    {
        if ( !close() )
            err(L"an error occured while closing the handle\n");
    }
}


BOOL
pwn::windows::alpc::Base::close()
{
    dbg(L"alpc::base - closing handle %p\n", m_AlpcSocketHandle);
    BOOL bRes = NT_SUCCESS(::NtAlpcDisconnectPort(m_AlpcSocketHandle, 0));
    if ( bRes )
        m_AlpcSocketHandle = INVALID_HANDLE_VALUE;
    return bRes;
}


pwn::windows::alpc::Message
pwn::windows::alpc::Base::send_and_receive(HANDLE hSocket, pwn::windows::alpc::Message& MsgIn)
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
        pwn::windows::alpc::Message MsgOut(lpRawMsgOut.get(), dwMsgOutLen);
        return MsgOut;
    }

    throw std::exception("NtAlpcSendWaitReceivePort() failed");
}


pwn::windows::alpc::Message
pwn::windows::alpc::Base::send_and_receive(HANDLE hSocket, const std::vector<BYTE>& messageData)
{
    Message MsgIn(messageData);
    return send_and_receive(hSocket, MsgIn);
}


HANDLE
pwn::windows::alpc::Base::SocketHandle()
{
    return m_AlpcSocketHandle;
}


std::wstring
pwn::windows::alpc::Base::PortName()
{
    return m_PortName;
}


////////////////////////////////////////////////////////////////////
//
// ALPC server
//


pwn::windows::alpc::Server::Server(const std::wstring& PortName) : Base(PortName)
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

    dbg(L"alpc::server - got handle {} for port '{}'\n", m_AlpcSocketHandle, m_PortName);
}


pwn::windows::alpc::Server::~Server()
{
    dbg(L"alpc::server - closing server...");
}


auto
pwn::windows::alpc::Server::accept() -> Result<PHANDLE>
{
    auto hAlpcClientSocket       = INVALID_HANDLE_VALUE;
    Message ConnectionRequestMsg = {};
    PHANDLE NewClientHandle      = nullptr;

    //
    // Wait for initial request
    //
    DWORD OriginalMsgSize = ConnectionRequestMsg.Size() & MAXDWORD;
    NTSTATUS Status       = ::NtAlpcSendWaitReceivePort(
        m_AlpcSocketHandle,
        0,
        nullptr,
        nullptr,
        ConnectionRequestMsg.Get(), // ReceiveMessage
        &OriginalMsgSize,           // BufferLength
        nullptr,
        nullptr);

    if ( !NT_SUCCESS(Status) )
    {
        ntperror(L"NtAlpcSendWaitReceivePort()", Status);
        return Err(ErrorCode::AlpcError);
    }

    pwn::utils::hexdump((PBYTE)&ConnectionRequestMsg.m_PortMessage, OriginalMsgSize);

    //
    // If the message was of valid type (i.e. request), we can accept the connection
    //
    if ( ConnectionRequestMsg.m_PortMessage.MessageId != LPC_CONNECTION_REQUEST )
    {
        err(L"Unexpected message type received: {}", ConnectionRequestMsg.m_PortMessage.MessageId);
        return Err(ErrorCode::AlpcError);
    }

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
        return Err(ErrorCode::AlpcError);
    }

    *NewClientHandle = hAlpcClientSocket;
    return Ok(NewClientHandle);
}


////////////////////////////////////////////////////////////////////
//
// ALPC client
//

pwn::windows::alpc::Client::Client(const std::wstring& PortName) : Base(PortName)
{
    if ( !reconnect() )
        throw std::runtime_error("failed to establish connection");
}


pwn::windows::alpc::Client::~Client()
{
    dbg(L"alpc::client - closing client");
}


auto
pwn::windows::alpc::Client::reconnect() -> bool
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

    dbg(L"alpc::client - port connected");
    return true;
}


pwn::windows::alpc::Message
pwn::windows::alpc::Client::sr(const std::vector<BYTE>& messageData)
{
    return send_and_receive(m_AlpcSocketHandle, messageData);
}

pwn::windows::alpc::Message
pwn::windows::alpc::Client::sr(Message& message)
{
    return send_and_receive(m_AlpcSocketHandle, message);
}
