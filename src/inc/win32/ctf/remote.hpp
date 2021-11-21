#pragma once

#include "common.hpp"
#include "tube.hpp"
#include "handle.hpp"
#include "utils.hpp"

#include <winsock2.h>


namespace pwn::win::ctf
{


///
/// A Remote session (pwntools-like)
///
class Remote : public Tube
{
public:
    PWNAPI Remote(_In_ std::wstring const& host, _In_ u16 port);
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
    SOCKET m_socket;
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

    ::pwn::utils::GenericHandle<HANDLE> m_hProcess;

    HANDLE m_ChildPipeStdin  = INVALID_HANDLE_VALUE;
    HANDLE m_ChildPipeStdout = INVALID_HANDLE_VALUE;
    HANDLE m_ParentStdin     = ::GetStdHandle(STD_INPUT_HANDLE);
    HANDLE m_ParentStdout    = ::GetStdHandle(STD_OUTPUT_HANDLE);
};

}