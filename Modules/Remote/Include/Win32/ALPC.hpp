#pragma once

#include "Common.hpp"
#include "Handle.hpp"


/********************************************************************************
 *
 * ALPC structures & definitions
 *
 * ref:
 * https://github.com/hugsy/ldos-ionescu007/blob/master/src/ldos/alpc.h
 * https://github.com/processhacker/processhacker/blob/master/phnt/include/ntlpcapi.h
 *
 ********************************************************************************/

#define LPC_REQUEST 1
#define LPC_REPLY 2
#define LPC_DATAGRAM 3
#define LPC_LOST_REPLY 4
#define LPC_PORT_CLOSED 5
#define LPC_CLIENT_DIED 6
#define LPC_EXCEPTION 7
#define LPC_DEBUG_EVENT 8
#define LPC_ERROR_EVENT 9
#define LPC_CONNECTION_REQUEST 10

#define ALPC_MSGFLG_REPLY_MESSAGE 0x1
#define ALPC_MSGFLG_LPC_MODE 0x2            // ?
#define ALPC_MSGFLG_RELEASE_MESSAGE 0x10000 // dbg
#define ALPC_MSGFLG_SYNC_REQUEST 0x20000    // dbg
#define ALPC_MSGFLG_WAIT_USER_MODE 0x100000
#define ALPC_MSGFLG_WAIT_ALERTABLE 0x200000
#define ALPC_MSGFLG_WOW64_CALL 0x80000000 // dbg

#define ALPC_MESSAGE_SECURITY_ATTRIBUTE 0x80000000
#define ALPC_MESSAGE_VIEW_ATTRIBUTE 0x40000000
#define ALPC_MESSAGE_CONTEXT_ATTRIBUTE 0x20000000
#define ALPC_MESSAGE_HANDLE_ATTRIBUTE 0x10000000
#define ALPC_MESSAGE_TOKEN_ATTRIBUTE 0x8000000
#define ALPC_MESSAGE_DIRECT_ATTRIBUT 0x4000000
#define ALPC_MESSAGE_WORK_ON_BEHALF_ATTRIBUTE 0x2000000
/*
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
        ULONG CallbackId;      // only valid for LPC_REQUEST messages
    };
} PORT_MESSAGE, *PPORT_MESSAGE;

typedef struct _ALPC_MESSAGE_ATTRIBUTES
{
    ULONG AllocatedAttributes;
    ULONG ValidAttributes;
} ALPC_MESSAGE_ATTRIBUTES, *PALPC_MESSAGE_ATTRIBUTES;

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
} ALPC_PORT_ATTRIBUTES, *PALPC_PORT_ATTRIBUTES;
*/
/*
EXTERN_C_START

NTSYSAPI NTSTATUS NTAPI
AlpcInitializeMessageAttribute(
    _In_ ULONG AttributeFlags,
    _Out_opt_ PALPC_MESSAGE_ATTRIBUTES Buffer,
    _In_ ULONG BufferSize,
    _Out_ PULONG RequiredBufferSize);


NTSYSCALLAPI NTSTATUS NTAPI
NtAlpcConnectPort(
    __out PHANDLE PortHandle,
    __in PUNICODE_STRING PortName,
    __in_opt POBJECT_ATTRIBUTES ObjectAttributes,
    __in_opt PALPC_PORT_ATTRIBUTES PortAttributes,
    __in ULONG Flags,
    __in_opt PSID RequiredServerSid,
    __inout_opt PPORT_MESSAGE ConnectionMessage,
    __inout_opt PULONG BufferLength,
    __inout_opt PALPC_MESSAGE_ATTRIBUTES OutMessageAttributes,
    __inout_opt PALPC_MESSAGE_ATTRIBUTES InMessageAttributes,
    __in_opt PLARGE_INTEGER Timeout);


NTSYSCALLAPI NTSTATUS NTAPI
NtAlpcSendWaitReceivePort(
    __in HANDLE PortHandle,
    __in ULONG Flags,
    __in_opt PPORT_MESSAGE SendMessage_,
    __in_opt PALPC_MESSAGE_ATTRIBUTES SendMessageAttributes,
    __inout_opt PPORT_MESSAGE ReceiveMessage,
    __inout_opt PULONG BufferLength,
    __inout_opt PALPC_MESSAGE_ATTRIBUTES ReceiveMessageAttributes,
    __in_opt PLARGE_INTEGER Timeout);


NTSYSCALLAPI NTSTATUS NTAPI
NtAlpcDisconnectPort(_In_ HANDLE PortHandle, _In_ ULONG Flags);


NTSYSCALLAPI NTSTATUS NTAPI
NtAlpcCreatePort(
    _Out_ PHANDLE PortHandle,
    _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_opt_ PALPC_PORT_ATTRIBUTES PortAttributes);


NTSYSCALLAPI NTSTATUS NTAPI
NtAlpcAcceptConnectPort(
    _Out_ PHANDLE PortHandle,
    _In_ HANDLE ConnectionPortHandle,
    _In_ ULONG Flags,
    _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_opt_ PALPC_PORT_ATTRIBUTES PortAttributes,
    _In_opt_ PVOID PortContext,
    _In_reads_bytes_(ConnectionRequest->u1.s1.TotalLength) PPORT_MESSAGE ConnectionRequest,
    _Inout_opt_ PALPC_MESSAGE_ATTRIBUTES ConnectionMessageAttributes,
    _In_ BOOLEAN AcceptConnection);

EXTERN_C_END
*/
#ifdef _WIN64
#define ALPC_PORT_MAXIMUM_MESSAGE_LENGTH 512
#else
#define ALPC_PORT_MAXIMUM_MESSAGE_LENGTH 256
#endif


namespace pwn::Remote::ALPC
{

///
///@brief Managed handle for ALPC, auto-call `NtAlpcDisconnectPort` on close
///
///@note SC_HANDLE = struct SC_HANDLE__
///
using AlpcHandle = GenericHandle<
    void,
    [](HANDLE h)
    {
        NtAlpcDisconnectPort(h, 0);
    }>;

class Message
{
public:
    PWNAPI
    Message(const std::vector<BYTE>& data = {});
    PWNAPI
    Message(const PBYTE lpRawData, const DWORD dwRawDataLength);
    PWNAPI ~Message();

    PWNAPI PPORT_MESSAGE
    Get();
    PWNAPI SIZE_T
    Size() const;
    PWNAPI std::vector<BYTE>
    Data() const;

    PORT_MESSAGE m_PortMessage {0};

private:
    std::vector<BYTE> m_Data;

    // this represents the ALPC contiguously built with header+data
    PPORT_MESSAGE m_AlpcRawMessage = nullptr;
};


///
///@brief ALPC base class definition
///
class Base
{
public:
    ///
    ///@brief Check class instance validity
    ///
    ///@return true
    ///@return false
    ///
    explicit operator bool() const
    {
        return m_Valid;
    }

    ///
    ///@brief Get the socket handle
    ///
    ///@return HANDLE
    ///
    HANDLE
    SocketHandle() const;

    ///
    ///@brief Get the port path
    ///
    ///@return PWNAPI
    ///
    std::wstring
    PortName() const;

    ///
    /// @brief
    ///
    ///
    auto
    SendAndReceive(const HANDLE hSocket, const std::vector<BYTE>& messageData = {}) -> Result<Message>;

    ///
    /// @brief
    ///
    ///
    auto
    SendAndReceive(const HANDLE hSocket, Message& message) -> Result<Message>;

protected:
    ///
    ///@brief Construct a new Base object
    ///@param PortName
    ///
    Base(std::wstring const& PortName);

    ///
    ///@brief Destroy the Base object
    ///
    ~Base();

    bool m_Valid;
    AlpcHandle m_AlpcSocketHandle;
    std::wstring m_PortName;

private:
    BOOL
    close();
};


///
///@brief ALPC server class definition
///
class Server : public Base
{
public:
    ///
    ///@brief Construct a new Server object
    ///
    ///@param PortName  the path to the port
    ///
    Server(const std::wstring& PortName);

    ///
    ///@brief Destroy the Server object
    ///
    ~Server();

    ///
    /// @brief Wait an accept a new ALPC connection.
    ///
    /// @return A client socket handle
    ///
    auto
    Accept() -> Result<HANDLE>;
};


///
///@brief ALPC client class definition
///
class Client : public Base
{
public:
    ///
    ///@brief Construct a new Client object
    ///
    ///@param PortName
    ///
    Client(const std::wstring& PortName);

    ///
    ///@brief Destroy the Client object
    ///
    ///
    ~Client();

    ///
    /// @brief Send and receive
    ///
    /// @param messageData
    /// @return Message
    ///
    auto
    sr(const std::vector<BYTE>& messageData = {}) -> Result<Message>;


    ///
    /// @brief
    ///
    /// @param messageData
    /// @return Message
    ///
    auto
    sr(Message& messageData) -> Result<Message>;
};
} // namespace pwn::Remote::ALPC
