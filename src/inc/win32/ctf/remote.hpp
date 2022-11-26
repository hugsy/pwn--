#pragma once

#include <winsock2.h>

#include "common.hpp"
#include "handle.hpp"
#include "tube.hpp"
#include "utils.hpp"


namespace pwn::windows::ctf
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
class Remote : public Tube
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
    recv_internal(_In_ size_t size);


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


} // namespace pwn::windows::ctf
