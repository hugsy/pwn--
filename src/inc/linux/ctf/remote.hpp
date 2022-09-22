#pragma once

#include <sys/socket.h>
#include <sys/types.h>

#include "common.hpp"
#include "handle.hpp"
#include "tube.hpp"
#include "utils.hpp"


namespace pwn::linux::ctf
{


///
/// A Remote session (pwntools-like)
///
class Remote : public Tube
{
public:
    PWNAPI
    Remote(_In_ std::wstring const& host, _In_ u16 port);
    PWNAPI ~Remote();

protected:
    auto
    __send_internal(_In_ std::vector<u8> const& out) -> size_t;

    auto
    __recv_internal(_In_ size_t size) -> std::vector<u8>;

    auto
    __peek_internal() -> size_t;


private:
    auto
    init() -> bool;

    auto
    connect() -> bool;

    auto
    disconnect() -> bool;

    auto
    cleanup() -> bool;

    auto
    reconnect() -> bool;

    std::wstring m_host;
    std::wstring m_protocol;
    u16 m_port;
    int m_socket;
};


///
/// A Process session (pwntools-like)
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

    ::pwn::UniqueHandle m_hProcess;

    int m_ChildPipeStdin  = -1;
    int m_ChildPipeStdout = -1;
    int m_ParentStdin     = -1;
    int m_ParentStdout    = -1;
};

} // namespace pwn::linux::ctf
