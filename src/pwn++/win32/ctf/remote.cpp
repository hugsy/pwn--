#include "win32/ctf/remote.hpp"

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
#include "pwn.hpp"
#include "handle.hpp"
#include "log.hpp"
#include "tube.hpp"
#include "utils.hpp"
// clang-format on

#pragma comment(lib, "ws2_32.lib")

extern struct pwn::GlobalContext pwn::Context;


pwn::windows::ctf::Remote::Remote(std::wstring_view const& host, const u16 port) :
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


pwn::windows::ctf::Remote::~Remote()
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


auto
pwn::windows::ctf::Remote::__send_internal(_In_ std::vector<u8> const& out) -> size_t
{
    if ( m_State != SocketState::Connected )
    {
        return 0;
    }

    auto res = ::send(m_Socket, reinterpret_cast<const char*>(&out[0]), out.size() & 0xffff, 0);
    if ( res == SOCKET_ERROR )
    {
        err(L"send() function: {#x}", ::WSAGetLastError());
        return 0;
    }

    dbg(L"sent {} bytes\n", out.size());
    if ( pwn::Context.log_level == pwn::log::LogLevel::Debug )
    {
        pwn::utils::hexdump(out);
    }

    return out.size();
}


auto
pwn::windows::ctf::Remote::__recv_internal(_In_ size_t size = PWN_TUBE_PIPE_DEFAULT_SIZE) -> std::vector<u8>
{
    if ( m_State != SocketState::Connected )
    {
        return {};
    }

    std::vector<u8> cache_data;
    size_t idx = 0;

    size = min(size, PWN_TUBE_PIPE_DEFAULT_SIZE);

    //
    // Try to read from the cache
    //
    if ( !m_receive_buffer.empty() )
    {
        auto sz = min(size, m_receive_buffer.size());
        std::copy(m_receive_buffer.begin(), m_receive_buffer.begin() + sz, std::back_inserter(cache_data));

        m_receive_buffer.erase(m_receive_buffer.begin(), m_receive_buffer.begin() + sz);

        //
        // check if the buffer is already full with data from cache
        //
        if ( cache_data.size() >= size )
        {
            dbg(L"recv2 {} bytes\n", cache_data.size());
            if ( pwn::Context.log_level == pwn::log::LogLevel::Debug )
            {
                pwn::utils::hexdump(cache_data);
            }
            return cache_data;
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
        pwn::log::perror(L"recv()");
        throw std::runtime_error("::recv() failed");
    }
    else
    {
        usize sz = cache_data.size() + res;
        if ( sz )
        {
            network_data.resize(sz);
            dbg(L"recv {} bytes", sz);
            if ( pwn::Context.log_level == pwn::log::LogLevel::Debug )
            {
                pwn::utils::hexdump(network_data);
            }
        }
    }
    return network_data;
}


auto
pwn::windows::ctf::Remote::__peek_internal() -> size_t
{
    if ( m_State != SocketState::Connected )
    {
        return 0;
    }

    auto buf = std::make_unique<u8[]>(PWN_TUBE_PIPE_DEFAULT_SIZE);
    auto res = ::recv(m_Socket, reinterpret_cast<char*>(buf.get()), PWN_TUBE_PIPE_DEFAULT_SIZE, MSG_PEEK);
    if ( res == SOCKET_ERROR )
    {
        pwn::log::perror(L"recv()");
        throw std::runtime_error("::peek() failed");
    }

    return res;
}


auto
pwn::windows::ctf::Remote::InitializeSocket() -> Result<bool>
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
        err(L"socket() failed: {#x}", ::WSAGetLastError());
        return Err(ErrorCode::InitializationFailed);
    }

    return Ok(true);
}


auto
pwn::windows::ctf::Remote::Connect() -> Result<bool>
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
    inet_pton(AF_INET, pwn::utils::StringLib::To<std::string>(m_Host).c_str(), &sin.sin_addr.s_addr);
    sin.sin_port = htons(m_Port);

    if ( ::connect(m_Socket, (SOCKADDR*)&sin, sizeof(sin)) == SOCKET_ERROR )
    {
        err(L"connect() failed: {:#x}", ::WSAGetLastError());
        return Err(ErrorCode::ConnectionError);
    }

    m_State = SocketState::Connected;
    dbg(L"connected to {}:{}", m_Host.c_str(), m_Port);
    return Ok(true);
}


auto
pwn::windows::ctf::Remote::Disconnect() -> Result<bool>
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
pwn::windows::ctf::Remote::Reconnect() -> bool
{
    return Success(Disconnect()) && Success(Connect());
}


///
/// Process
///
auto
pwn::windows::ctf::Process::__send_internal(_In_ std::vector<u8> const& out) -> size_t
{
    DWORD dwRead  = 0;
    auto bSuccess = ::WriteFile(m_ChildPipeStdin, &out[0], out.size() & 0xffffffff, &dwRead, nullptr);
    if ( bSuccess == 0 )
    {
        pwn::log::perror(L"ReadFile()");
    }

    return dwRead;
}


auto
pwn::windows::ctf::Process::__recv_internal(_In_ size_t size) -> std::vector<u8>
{
    DWORD dwRead;
    std::vector<u8> out;

    size = min(size, PWN_TUBE_PIPE_DEFAULT_SIZE) & 0xffffffff;
    out.resize(size);

    auto bSuccess = ::ReadFile(m_ChildPipeStdout, &out[0], size & 0xffffffff, &dwRead, nullptr);
    if ( bSuccess == 0 )
    {
        pwn::log::perror(L"ReadFile()");
    }

    return out;
}


auto
pwn::windows::ctf::Process::__peek_internal() -> size_t
{
    throw std::exception("not implemented");
}


auto
pwn::windows::ctf::Process::create_pipes() -> bool
{
    SECURITY_ATTRIBUTES sa  = {0};
    sa.nLength              = sizeof(SECURITY_ATTRIBUTES);
    sa.bInheritHandle       = 1;
    sa.lpSecurityDescriptor = nullptr;

    return (CreatePipe(&m_ParentStdin, &m_ChildPipeStdin, &sa, 0) != 0) &&
           (CreatePipe(&m_ParentStdout, &m_ChildPipeStdout, &sa, 0) != 0) &&
           (SetHandleInformation(m_ChildPipeStdout, HANDLE_FLAG_INHERIT, 0) != 0);
}


auto
pwn::windows::ctf::Process::spawn_process() -> bool
{
    if ( !create_pipes() )
    {
        err(L"failed to create pipes\n");
        return false;
    }

    STARTUPINFO si         = {0};
    PROCESS_INFORMATION pi = {nullptr};

    si.cb         = sizeof(STARTUPINFO);
    si.hStdError  = m_ChildPipeStdout;
    si.hStdOutput = m_ChildPipeStdout;
    si.hStdInput  = m_ChildPipeStdin;
    si.dwFlags |= STARTF_USESTDHANDLES;

    if ( ::CreateProcessW(
             nullptr,
             m_commandline.data(),
             nullptr,
             nullptr,
             1,
             0,
             nullptr,
             nullptr,
             reinterpret_cast<LPSTARTUPINFOW>(&si),
             reinterpret_cast<LPPROCESS_INFORMATION>(&pi)) != 0 )
    {
        // m_hProcess = pwn::UniqueHandle(pi.hProcess);
        ::CloseHandle(pi.hThread);
        return true;
    }

    return false;
}
