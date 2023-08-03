#include "CTF/Linux/Remote.hpp"

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

namespace pwn
{

extern struct GlobalContext Context;

CTF::Remote::Remote(std::wstring_view const& host, const u16 port) :
    m_Host(host),
    m_Port(port),
    m_Protocol(L"tcp"),
    m_Socket(-1)
{
    if ( !InitializeSocket() || Failed(Connect()) )
    {
        throw std::runtime_error("connection to host failed");
    }
}

CTF::Remote::Remote(std::string_view const& host, const u16 port) :
    CTF::Remote::Remote(Utils::StringLib::To<std::wstring>(std::string(host)), port)
{
}

CTF::Remote::~Remote()
{
    Disconnect();
}


Result<bool>
CTF::Remote::Connect()
{
    sockaddr_in sin = {0};
    sin.sin_family  = AF_INET;
    sin.sin_port    = ::htons(m_Port);
    auto host       = Utils::StringLib::To<std::string>(m_Host);

    ::inet_pton(AF_INET, host.c_str(), &sin.sin_addr.s_addr);

    if ( ::connect(m_Socket, (struct sockaddr*)&sin, sizeof(sin)) < 0 )
    {
        ::perror("connect()");
        return Err(ErrorCode::ExternalApiCallFailed);
    }

    dbg("connected to {}:{}", host, m_Port);
    return Ok(true);
}


Result<bool>
CTF::Remote::Disconnect()
{
    auto res = true;

    info(L"Closing socket {}", m_Socket);

    if ( ::close(m_Socket) < 0 )
    {
        ::perror("closesocket()");
        return Err(ErrorCode::ExternalApiCallFailed);
    }

    m_Socket = 0;
    info(L"Session to {}:{} closed", m_Host.c_str(), m_Port);
    return Ok(res);
}


Result<bool>
CTF::Remote::Reconnect()
{
    return Success(Disconnect()) && Success(Connect());
}


Result<usize>
CTF::Remote::send_internal(_In_ std::vector<u8> const& out)
{
    const bool is_debug = true; // std::get<0>(Context::get_log_level()) == Log::LogLevel::Debug
    auto res            = ::send(m_Socket, reinterpret_cast<const char*>(&out[0]), out.size() & 0xffff, 0);
    if ( res < 0 )
    {
        ::perror("send()");
        return Err(ErrorCode::ExternalApiCallFailed);
    }

    dbg(L"sent {} bytes", out.size());
    if ( is_debug )
    {
        Utils::Hexdump(out);
    }

    return Ok(out.size());
}


Result<std::vector<u8>>
CTF::Remote::recv_internal(_In_ usize size = Net::Tube::PIPE_DEFAULT_SIZE)
{
    std::vector<u8> cache_data;
    size_t idx    = 0;
    bool is_debug = true; // (std::get<0>(pwn::context::get_log_level()) == Log::LogLevel::Debug);

    size = MIN(size, Tube::PIPE_DEFAULT_SIZE);

    // Try to read from the cache
    if ( !m_receive_buffer.empty() )
    {
        auto sz = MIN(size, m_receive_buffer.size());
        std::copy(m_receive_buffer.begin(), m_receive_buffer.begin() + sz, std::back_inserter(cache_data));

        m_receive_buffer.erase(m_receive_buffer.begin(), m_receive_buffer.begin() + sz);

        // check if the buffer is already full with data from cache
        if ( cache_data.size() >= size )
        {
            dbg("recv2 {} bytes", cache_data.size());
            if ( is_debug )
            {
                Utils::Hexdump(cache_data);
            }
            return Ok(std::move(cache_data));
        }

        // otherwise, read from network
        size -= sz;
        idx = sz;
    }

    std::vector<u8> network_data(cache_data);
    network_data.resize(cache_data.size() + size);

    auto res = ::recv(m_Socket, reinterpret_cast<char*>(&network_data[idx]), (u32)size, 0);
    if ( res < 0 )
    {
        ::perror("recv()");
        throw std::runtime_error("::recv() failed");
    }
    else
    {
        size_t sz = cache_data.size() + res;
        if ( sz )
        {
            network_data.resize(sz);
            dbg("recv {} bytes\n", sz);
            if ( is_debug )
            {
                Utils::Hexdump(&network_data[0], sz);
            }
        }
    }
    return Ok(std::move(network_data));
}


Result<usize>
CTF::Remote::peek_internal()
{
    auto buf = std::make_unique<u8[]>(Tube::PIPE_DEFAULT_SIZE);
    int res  = ::recv(m_Socket, reinterpret_cast<char*>(buf.get()), Tube::PIPE_DEFAULT_SIZE, MSG_PEEK);
    if ( res < 0 )
    {
        ::perror("recv()");
        throw std::runtime_error("::peek() failed");
    }

    return Ok(static_cast<usize>(res));
}


bool
CTF::Remote::InitializeSocket()
{
    if ( m_Protocol == L"tcp" )
    {
        m_Socket = ::socket(AF_INET, SOCK_STREAM, 0);
        // TODO: add more protocols
    }
    else
    {
        throw std::invalid_argument("m_Protocol");
    }

    if ( m_Socket < 0 )
    {
        ::perror("socket()");
        return false;
    }

    return true;
}


} // namespace pwn
