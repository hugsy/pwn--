#pragma once

#include <winsock2.h>

#include "Common.hpp"
#include "Handle.hpp"
#include "Tube.hpp"
#include "Utils.hpp"


namespace pwn::CTF
{

enum class SocketState : u8
{
    Disconnected,
    Initialized,
    WaitingForConnection,
    Connected,
};

///
///@brief Remote session
///
class Remote : public Net::Tube
{
public:
    PWNAPI
    Remote(std::wstring_view const& host, const u16 port);
    PWNAPI ~Remote();

    auto
    Connect() -> Result<bool>;

    auto
    Disconnect() -> Result<bool>;

    auto
    Reconnect() -> bool;


protected:
    Result<usize>
    send_internal(_In_ std::vector<u8> const& out);


    Result<std::vector<u8>>
    recv_internal(_In_ usize size);


    Result<usize>
    peek_internal();


private:
    auto
    InitializeSocket() -> Result<bool>;

    const std::wstring m_Host;
    const std::wstring m_Protocol;
    const u16 m_Port;

    SOCKET m_Socket;
    SocketState m_State;
};


} // namespace CTF
