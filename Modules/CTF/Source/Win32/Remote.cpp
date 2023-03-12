#include "CTF/Win32/Remote.hpp"

#include <winsock2.h>
#include <ws2tcpip.h>

#include <functional>
#include <iostream>
#include <iterator>
#include <queue>
#include <stdexcept>
#include <string>
#include <thread>
#include <utility>

// clang-format off
#include "Context.hpp"
#include "Handle.hpp"
#include "Log.hpp"
#include "Tube.hpp"
#include "Utils.hpp"
// clang-format on


extern struct GlobalContext Context;

///
/// @file Remote.cpp
///

CTF::Remote::Remote(std::wstring_view const& host, const u16 port) :
    m_Host(host),
    m_Port(port),
    m_Protocol(L"tcp"),
    m_State(SocketState::Disconnected),
    m_Socket(INVALID_SOCKET)
{
    WSADATA wsaData = {0};
    if ( ::WSAStartup(MAKEWORD(2, 2), &wsaData) == NO_ERROR )
    {
        m_State = SocketState::Initialized;
        Connect();
    }
    else
    {
        err(L"WSAStartup() failed: {#x}", ::WSAGetLastError());
    }
}


CTF::Remote::~Remote()
{
    if ( m_State >= SocketState::Connected )
    {
        Disconnect();
    }

    if ( m_State >= SocketState::Initialized )
    {
        ::WSACleanup();
    }
}


Result<usize>
CTF::Remote::send_internal(_In_ std::vector<u8> const& out)
{
    if ( m_State != SocketState::Connected )
    {
        return Err(ErrorCode::NotConnected);
    }

    auto res = ::send(m_Socket, reinterpret_cast<const char*>(&out[0]), out.size() & 0xffff, 0);
    if ( res == SOCKET_ERROR )
    {
        err(L"send() function: {#x}", ::WSAGetLastError());
        return Err(ErrorCode::ExternalApiCallFailed);
    }

    dbg(L"sent {} bytes", out.size());
    if ( Context.LogLevel == Log::LogLevel::Debug )
    {
        Utils::hexdump(out);
    }

    return Ok(out.size());
}


Result<std::vector<u8>>
CTF::Remote::recv_internal(_In_ usize size = Net::Tube::PIPE_DEFAULT_SIZE)
{
    if ( m_State != SocketState::Connected )
    {
        return Err(ErrorCode::NotConnected);
    }

    std::vector<u8> cache_data;
    usize idx = 0;

    size = MIN(size, Net::Tube::PIPE_DEFAULT_SIZE);

    //
    // Try to read from the cache
    //
    if ( !m_receive_buffer.empty() )
    {
        const usize sz = MIN(size, (usize)m_receive_buffer.size());
        std::copy(m_receive_buffer.begin(), m_receive_buffer.begin() + sz, std::back_inserter(cache_data));

        m_receive_buffer.erase(m_receive_buffer.begin(), m_receive_buffer.begin() + sz);

        //
        // check if the buffer is already full with data from cache
        //
        if ( cache_data.size() >= size )
        {
            dbg(L"recv2 {} bytes\n", cache_data.size());
            if ( Context.LogLevel == Log::LogLevel::Debug )
            {
                Utils::hexdump(cache_data);
            }
            return Ok(cache_data);
        }

        //
        // otherwise, read from network
        //
        size -= sz;
        idx = sz;
    }

    std::vector<u8> network_data(cache_data);
    network_data.resize(cache_data.size() + size);

    auto res = ::recv(m_Socket, reinterpret_cast<char*>(&network_data[idx]), (u32)size, 0);
    if ( res == SOCKET_ERROR )
    {
        ULONG reason = ::WSAGetLastError();
        switch ( reason )
        {
        case WSAECONNABORTED:
        case WSAECONNRESET:
            return Err(ErrorCode::ConnectionError, reason);

        default:
            return Err(ErrorCode::ExternalApiCallFailed, reason);
        }
    }

    usize sz = cache_data.size() + res;
    if ( sz )
    {
        network_data.resize(sz);
        dbg(L"recv {} bytes", sz);
        if ( Context.LogLevel == Log::LogLevel::Debug )
        {
            Utils::hexdump(network_data);
        }
    }

    return Ok(network_data);
}


Result<usize>
CTF::Remote::peek_internal()
{
    if ( m_State != SocketState::Connected )
    {
        return Err(ErrorCode::NotConnected);
    }

    auto buf  = std::make_unique<u8[]>(Net::Tube::PIPE_DEFAULT_SIZE);
    usize res = ::recv(m_Socket, reinterpret_cast<char*>(buf.get()), Net::Tube::PIPE_DEFAULT_SIZE, MSG_PEEK);
    if ( res == SOCKET_ERROR )
    {
        return Err(ErrorCode::ExternalApiCallFailed);
    }

    return Ok(res);
}


auto
CTF::Remote::InitializeSocket() -> Result<bool>
{
    if ( m_Protocol == L"tcp" )
    {
        m_Socket = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP); // TODO: add more proto
    }
    else
    {
        return Err(ErrorCode::InvalidParameter);
    }

    if ( m_Socket == INVALID_SOCKET )
    {
        return Err(ErrorCode::InitializationFailed, ::WSAGetLastError());
    }

    return Ok(true);
}


auto
CTF::Remote::Connect() -> Result<bool>
{
    if ( m_State == SocketState::Connected )
    {
        return Ok(true);
    }

    if ( m_State != SocketState::Initialized )
    {
        return Err(ErrorCode::NotInitialized);
    }

    //
    // Initialize the socket
    //
    if ( Failed(InitializeSocket()) )
    {
        return Err(ErrorCode::InitializationFailed);
    }

    //
    // Connect to the remote host
    //
    sockaddr_in sin = {0};
    sin.sin_family  = AF_INET;
    inet_pton(AF_INET, Utils::StringLib::To<std::string>(m_Host).c_str(), &sin.sin_addr.s_addr);
    sin.sin_port = htons(m_Port);

    if ( ::connect(m_Socket, (SOCKADDR*)&sin, sizeof(sin)) == SOCKET_ERROR )
    {
        return Err(ErrorCode::ConnectionError, ::WSAGetLastError());
    }

    m_State = SocketState::Connected;
    dbg(L"connected to {}:{}", m_Host.c_str(), m_Port);
    return Ok(true);
}


auto
CTF::Remote::Disconnect() -> Result<bool>
{
    if ( m_State != SocketState::Connected )
    {
        return Err(ErrorCode::NotConnected);
    }

    auto bSuccess = (::closesocket(m_Socket) == SOCKET_ERROR);
    if ( bSuccess )
    {
        err(L"closesocket() failed: {}", ::WSAGetLastError());
    }
    else
    {
        dbg(L"session to {}:{} closed", m_Host.c_str(), m_Port);
        m_State = SocketState::Initialized;
    }

    return Ok(bSuccess);
}


auto
CTF::Remote::Reconnect() -> bool
{
    return Success(Disconnect()) && Success(Connect());
}
