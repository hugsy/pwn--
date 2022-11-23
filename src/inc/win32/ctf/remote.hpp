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
    auto
    __send_internal(_In_ std::vector<u8> const& out) -> size_t;

    auto
    __recv_internal(_In_ size_t size) -> std::vector<u8>;

    auto
    __peek_internal() -> size_t;


private:
    auto
    InitializeSocket() -> Result<bool>;

    const std::wstring m_Host;
    const std::wstring m_Protocol;
    const u16 m_Port;

    SOCKET m_Socket;
    SocketState m_State;
};


///
///@brief A Process session
///
class Process : public Tube
{
public:
    Process()  = default;
    ~Process() = default;

protected:
    auto
    __send_internal(_In_ std::vector<u8> const& out) -> size_t;

    auto
    __recv_internal(_In_ size_t size = PWN_TUBE_PIPE_DEFAULT_SIZE) -> std::vector<u8>;

    auto
    __peek_internal() -> size_t;


private:
    auto
    create_pipes() -> bool;

    auto
    spawn_process() -> bool;

    std::wstring m_processname;
    std::wstring m_commandline;

    pwn::UniqueHandle m_hProcess;

    HANDLE m_ChildPipeStdin  = INVALID_HANDLE_VALUE;
    HANDLE m_ChildPipeStdout = INVALID_HANDLE_VALUE;
    HANDLE m_ParentStdin     = ::GetStdHandle(STD_INPUT_HANDLE);
    HANDLE m_ParentStdout    = ::GetStdHandle(STD_OUTPUT_HANDLE);
};

} // namespace pwn::windows::ctf
