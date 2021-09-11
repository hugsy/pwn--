#include "linux/ctf/remote.hpp"

#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>

#include <algorithm>
#include <functional>
#include <iostream>
#include <iterator>
#include <queue>
#include <stdexcept>
#include <string>
#include <thread>
#include <utility>

#include "handle.hpp"
#include "log.hpp"
#include "tube.hpp"
#include "utils.hpp"


///
/// Remote
///
pwn::linux::ctf::Remote::Remote(_In_ std::wstring const& host, _In_ u16 port) : m_host(host), m_port(port), m_protocol(L"tcp"), m_socket(-1)
{
    if ( !connect() )
    {
        throw std::runtime_error("connection to host failed");
    }
}

pwn::linux::ctf::Remote::~Remote()
{
    disconnect();
}


auto
pwn::linux::ctf::Remote::__send_internal(_In_ std::vector<u8> const& out) -> size_t
{
    auto res = ::send(m_socket, reinterpret_cast<const char*>(&out[0]), out.size() & 0xffff, 0);
    if ( res < 0 )
    {
        err(L"send() function: %#x\n", errno);
        disconnect();
        return 0;
    }

    dbg(L"sent %d bytes\n", out.size());
    if ( std::get<0>(pwn::context::get_log_level()) == pwn::log::log_level_t::LOG_DEBUG )
    {
        pwn::utils::hexdump(out);
    }

    return out.size();
}


auto
pwn::linux::ctf::Remote::__recv_internal(_In_ size_t size = PWN_TUBE_PIPE_DEFAULT_SIZE) -> std::vector<u8>
{
    std::vector<u8> cache_data;
    size_t idx = 0;
    bool is_debug = (std::get<0>(pwn::context::get_log_level()) == pwn::log::log_level_t::LOG_DEBUG);

    size = MIN(size, PWN_TUBE_PIPE_DEFAULT_SIZE);

    // Try to read from the cache
    if ( !m_receive_buffer.empty() )
    {
        auto sz = MIN(size, m_receive_buffer.size());
        std::copy(m_receive_buffer.begin(), m_receive_buffer.begin() + sz, std::back_inserter(cache_data));

        m_receive_buffer.erase(m_receive_buffer.begin(), m_receive_buffer.begin() + sz);

        // check if the buffer is already full with data from cache
        if ( cache_data.size() >= size )
        {
            dbg(L"recv2 %d bytes\n", cache_data.size());
            if (is_debug)
            {
                pwn::utils::hexdump(cache_data);
            }
            return cache_data;
        }

        // otherwise, read from network
        size -= sz;
        idx = sz;
    }

    std::vector<u8> network_data(cache_data);
    network_data.resize(cache_data.size() + size);

    auto res = ::recv(m_socket, reinterpret_cast<char*>(&network_data[idx]), (u32)size, 0);
    if ( res < 0 )
    {
        err(L"recv() function: %#x\n", errno);
        throw std::runtime_error("::recv() failed");
    }
    else
    {
        size_t sz = cache_data.size() + res;
        if ( sz )
        {
            network_data.resize(sz);
            dbg(L"recv %d bytes\n", sz);
            if (is_debug)
            {
                pwn::utils::hexdump(&network_data[0], sz);
            }
        }
    }
    return network_data;
}


auto
pwn::linux::ctf::Remote::__peek_internal() -> size_t
{
    auto buf = std::make_unique<u8[]>(PWN_TUBE_PIPE_DEFAULT_SIZE);
    auto res = ::recv(m_socket, reinterpret_cast<char*>(buf.get()), PWN_TUBE_PIPE_DEFAULT_SIZE, MSG_PEEK);
    if ( res < 0 )
    {
        perror("recv()");
        throw std::runtime_error("::peek() failed");
    }

    return res;
}


auto
pwn::linux::ctf::Remote::init() -> bool
{
    if ( m_protocol == L"tcp" )
    {
        m_socket = ::socket(AF_INET, SOCK_STREAM, 0);
        // TODO: supporter d'autres proto
    }
    else
    {
        throw std::invalid_argument("m_protocol");
    }

    if ( m_socket < 0 )
    {
        err(L"socket() function: %#x\n", errno);
        cleanup();
        return false;
    }

    return true;
}


auto
pwn::linux::ctf::Remote::connect() -> bool
{
    if ( !init() )
    {
        return false;
    }

    sockaddr_in sin = {0};
    sin.sin_family  = AF_INET;
    sin.sin_port = htons(m_port);
    inet_pton(AF_INET, pwn::utils::widestring_to_string(m_host).c_str(), &sin.sin_addr.s_addr);

    if ( ::connect(m_socket, (struct sockaddr*)&sin, sizeof(sin)) < 0 )
    {
        err(L"connect() function failed with error: %#x\n", errno);
        disconnect();
        cleanup();
        return false;
    }

    dbg(L"connected to %s:%d\n", m_host.c_str(), m_port);
    return true;
}


auto
pwn::linux::ctf::Remote::disconnect() -> bool
{
    auto res = true;

    if ( ::close(m_socket) < 0 )
    {
        err(L"closesocket() function failed with error: %#x\n", errno);
        res = false;
    }

    cleanup();
    dbg(L"session to %s:%d closed\n", m_host.c_str(), m_port);
    return res;
}


auto
pwn::linux::ctf::Remote::cleanup() -> bool
{
    return true;
}


auto
pwn::linux::ctf::Remote::reconnect() -> bool
{
    return disconnect() && connect();
}


///
/// Process
///
auto
pwn::linux::ctf::Process::__send_internal(_In_ std::vector<u8> const& out) -> size_t
{
    auto bSuccess = false;
    u32 dwRead    = 0;
    // TODO
    // bSuccess = ::WriteFile(m_ChildPipeStdin, &out[0], out.size() & 0xffffffff, &dwRead, nullptr);
    if ( !bSuccess )
    {
        perror("write()");
    }

    return 0;
}


auto
pwn::linux::ctf::Process::__recv_internal(_In_ size_t size) -> std::vector<u8>
{
    auto bSuccess = false;
    u32 dwRead;
    std::vector<u8> out;

    size = MIN(size, PWN_TUBE_PIPE_DEFAULT_SIZE) & 0xffffffff;
    out.resize(size);

    // TODO
    // auto bSuccess = ::ReadFile(m_ChildPipeStdout, &out[0], size & 0xffffffff, &dwRead, nullptr);
    if ( !bSuccess )
    {
        perror("ReadFile()");
    }

    return out;
}


auto
pwn::linux::ctf::Process::__peek_internal() -> size_t
{
    throw std::runtime_error("not implemented");
}


auto
pwn::linux::ctf::Process::create_pipes() -> bool
{
    return false;
}


auto
pwn::linux::ctf::Process::spawn_process() -> bool
{
    if ( !create_pipes() )
    {
        err(L"failed to create pipes\n");
        return false;
    }

    // TODO
    throw std::runtime_error("not implemented");
    return false;
}
