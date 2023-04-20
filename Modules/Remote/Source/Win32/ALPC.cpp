#include "Win32/ALPC.hpp"

#include "Log.hpp"
#include "Utils.hpp"
#include "Win32/API.hpp"

using namespace pwn;

///
/// ALPC basic implementation
///
/// Some references:
/// - https://csandker.io/2022/05/24/Offensive-Windows-IPC-3-ALPC.html
/// - https://github.com/bnagy/alpcgo
///

namespace pwn::Remote::ALPC
{
#pragma region ALPC Messages


Message::Message(const std::vector<BYTE>& data) : m_Data(data), m_AlpcRawMessage(nullptr)
{
    m_PortMessage.u1.s1.DataLength  = m_Data.size() & USHRT_MAX;
    m_PortMessage.u1.s1.TotalLength = Size() & USHRT_MAX;
}


Message::Message(const PBYTE lpRawData, DWORD dwRawDataLength) : m_AlpcRawMessage(nullptr)
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


Message::~Message()
{
    dbg(L"alpc::message - destroying\n");
    if ( m_AlpcRawMessage )
    {
        ::HeapFree(::GetProcessHeap(), 0, m_AlpcRawMessage);
        m_AlpcRawMessage = nullptr;
    }
}


PPORT_MESSAGE
Message::Get()
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
Message::Size() const
{
    return sizeof(PORT_MESSAGE) + m_Data.size();
}

PWNAPI std::vector<BYTE>
Message::Data() const
{
    return m_Data;
}

#pragma endregion ALPC Messages


#pragma region ALPC Base class


Base::Base(std::wstring const& PortName) :
    m_PortName(PortName),
    m_AlpcSocketHandle(INVALID_HANDLE_VALUE),
    m_Valid(false)
{
    if ( PortName.starts_with(L"\\") == false )
    {
        throw std::exception("invalid port name");
    }
}


Base::~Base()
{
}


Result<Message>
Base::SendAndReceive(HANDLE hSocket, Message& MsgIn)
{
    if ( !m_Valid )
    {
        return Err(ErrorCode::NotInitialized);
    }

    usize dwMsgOutLen = 2048;
    auto lpRawMsgOut  = std::make_unique<u8[]>(dwMsgOutLen);

    NTSTATUS Status = Resolver::ntdll::NtAlpcSendWaitReceivePort(
        hSocket,
        0,
        MsgIn.Get(),
        nullptr,
        reinterpret_cast<PPORT_MESSAGE>(lpRawMsgOut.get()),
        &dwMsgOutLen,
        nullptr,
        nullptr);
    if ( !NT_SUCCESS(Status) )
    {
        Log::perror("NtAlpcSendWaitReceivePort()");
        return Err(ErrorCode::ExternalApiCallFailed);
    }

    Message MsgOut(lpRawMsgOut.get(), dwMsgOutLen);
    return MsgOut;
}


Result<Message>
Base::SendAndReceive(HANDLE hSocket, const std::vector<u8>& messageData)
{
    Message MsgIn(messageData);
    return SendAndReceive(hSocket, MsgIn);
}


HANDLE
Base::SocketHandle() const
{
    return m_AlpcSocketHandle.get();
}


std::wstring
Base::PortName() const
{
    return m_PortName;
}

#pragma endregion


#pragma region ALPC server

Server::Server(const std::wstring& PortName) : Base(PortName)
{
    UNICODE_STRING AlpcPortName;
    ::RtlInitUnicodeString(&AlpcPortName, m_PortName.c_str());

    OBJECT_ATTRIBUTES ObjectAttributes = {0};
    InitializeObjectAttributes(&ObjectAttributes, &AlpcPortName, 0, 0, 0);

    ALPC_PORT_ATTRIBUTES PortAttributes = {0};
    PortAttributes.MaxMessageLength     = ALPC_PORT_MAXIMUM_MESSAGE_LENGTH;

    HANDLE hPortSocket = INVALID_HANDLE_VALUE;

    NTSTATUS Status = Resolver::ntdll::NtAlpcCreatePort(&hPortSocket, &ObjectAttributes, &PortAttributes);
    if ( !NT_SUCCESS(Status) )
    {
        Log::ntperror(L"NtAlpcCreatePort", Status);
        return;
    }

    m_AlpcSocketHandle = AlpcHandle {hPortSocket};
    dbg(L"alpc::server - created listening handle {:p} for port '{}'", m_AlpcSocketHandle.get(), m_PortName.c_str());

    m_Valid = true;
}


Server::~Server()
{
    dbg(L"alpc::server - closing server...");
}


auto
Server::Accept() -> Result<HANDLE>
{
    HANDLE hAlpcClientSocket     = INVALID_HANDLE_VALUE;
    Message ConnectionRequestMsg = {};

    //
    // Wait for initial request
    //
    SIZE_T OriginalMsgSize = ConnectionRequestMsg.Size();
    NTSTATUS Status        = Resolver::ntdll::NtAlpcSendWaitReceivePort(
        m_AlpcSocketHandle.get(),
        0,
        nullptr,
        nullptr,
        ConnectionRequestMsg.Get(), // ReceiveMessage
        &OriginalMsgSize,           // BufferLength
        nullptr,
        nullptr);

    if ( !NT_SUCCESS(Status) )
    {
        Log::ntperror(L"NtAlpcSendWaitReceivePort()", Status);
        return Err(ErrorCode::AlpcError);
    }

    Utils::hexdump((PBYTE)&ConnectionRequestMsg.m_PortMessage, OriginalMsgSize);

    //
    // If the message was of valid type (i.e. request), we can accept the connection
    //
    if ( ConnectionRequestMsg.m_PortMessage.MessageId != LPC_CONNECTION_REQUEST )
    {
        err(L"Unexpected message type received: {}", ConnectionRequestMsg.m_PortMessage.MessageId);
        return Err(ErrorCode::AlpcError);
    }

    Status = Resolver::ntdll::NtAlpcAcceptConnectPort(
        &hAlpcClientSocket,
        m_AlpcSocketHandle.get(),
        0,
        nullptr,
        nullptr,
        nullptr,
        ConnectionRequestMsg.Get(),
        nullptr,
        true);
    if ( !NT_SUCCESS(Status) )
    {
        Log::ntperror(L"NtAlpcAcceptConnectPort()", Status);
        return Err(ErrorCode::AlpcError);
    }

    dbg(L"alpc::server - created client handle {:p} for port '{}'", hAlpcClientSocket, m_PortName.c_str());
    return Ok(hAlpcClientSocket);
}

#pragma endregion


#pragma region ALPC client


Client::Client(const std::wstring& PortName) : Base(PortName)
{
    UNICODE_STRING AlpcPortName;
    ::RtlInitUnicodeString(&AlpcPortName, m_PortName.c_str());

    HANDLE hPortSocket = INVALID_HANDLE_VALUE;
    NTSTATUS Status    = Resolver::ntdll::NtAlpcConnectPort(
        &hPortSocket,
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
        Log::ntperror(L"NtAlpcConnectPort()", Status);
        return;
    }

    m_AlpcSocketHandle = AlpcHandle {hPortSocket};

    dbg(L"alpc::client - connected to port '{}' (handle={:p}", m_PortName.c_str(), m_AlpcSocketHandle.get());
    m_Valid = true;
}


Client::~Client()
{
    dbg(L"alpc::client - closing client");
}


Result<Message>
Client::sr(const std::vector<u8>& messageData)
{
    return SendAndReceive(m_AlpcSocketHandle.get(), messageData);
}

Result<Message>
Client::sr(Message& message)
{
    return SendAndReceive(m_AlpcSocketHandle.get(), message);
}

#pragma endregion

} // namespace pwn::Remote::ALPC
