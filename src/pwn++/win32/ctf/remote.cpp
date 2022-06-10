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

extern struct pwn::globals_t pwn::globals;


///
/// Remote
///
pwn::windows::ctf::Remote::Remote(_In_ std::wstring const& host, _In_ u16 port) :
    m_host(host),
    m_port(port),
    m_protocol(L"tcp"),
    m_socket(INVALID_SOCKET)
{
    if ( !connect() )
    {
        throw std::runtime_error("connection to host failed");
    }
}

pwn::windows::ctf::Remote::~Remote()
{
    disconnect();
}


auto
pwn::windows::ctf::Remote::__send_internal(_In_ std::vector<u8> const& out) -> size_t
{
    auto res = ::send(m_socket, reinterpret_cast<const char*>(&out[0]), out.size() & 0xffff, 0);
    if ( res == SOCKET_ERROR )
    {
        err(L"send() function: %#x\n", ::WSAGetLastError());
        disconnect();
        return 0;
    }

    dbg(L"sent %d bytes\n", out.size());
    if ( pwn::globals.log_level == pwn::log::log_level_t::LOG_DEBUG )
    {
        pwn::utils::hexdump(out);
    }

    return out.size();
}


auto
pwn::windows::ctf::Remote::__recv_internal(_In_ size_t size = PWN_TUBE_PIPE_DEFAULT_SIZE) -> std::vector<u8>
{
    std::vector<u8> cache_data;
    size_t idx = 0;

    size = min(size, PWN_TUBE_PIPE_DEFAULT_SIZE);

    // Try to read from the cache
    if ( !m_receive_buffer.empty() )
    {
        auto sz = min(size, m_receive_buffer.size());
        std::copy(m_receive_buffer.begin(), m_receive_buffer.begin() + sz, std::back_inserter(cache_data));

        m_receive_buffer.erase(m_receive_buffer.begin(), m_receive_buffer.begin() + sz);

        // check if the buffer is already full with data from cache
        if ( cache_data.size() >= size )
        {
            dbg(L"recv2 %d bytes\n", cache_data.size());
            if ( pwn::globals.log_level == pwn::log::log_level_t::LOG_DEBUG )
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
    if ( res == SOCKET_ERROR )
    {
        pwn::log::perror(L"recv()");
        throw std::runtime_error("::recv() failed");
    }
    else
    {
        size_t sz = cache_data.size() + res;
        if ( sz )
        {
            network_data.resize(sz);
            dbg(L"recv %d bytes\n", sz);
            if ( pwn::globals.log_level == pwn::log::log_level_t::LOG_DEBUG )
            {
                pwn::utils::hexdump(&network_data[0], sz);
            }
        }
    }
    return network_data;
}


auto
pwn::windows::ctf::Remote::__peek_internal() -> size_t
{
    auto buf = std::make_unique<u8[]>(PWN_TUBE_PIPE_DEFAULT_SIZE);
    auto res = ::recv(m_socket, reinterpret_cast<char*>(buf.get()), PWN_TUBE_PIPE_DEFAULT_SIZE, MSG_PEEK);
    if ( res == SOCKET_ERROR )
    {
        pwn::log::perror(L"recv()");
        throw std::runtime_error("::peek() failed");
    }

    return res;
}


auto
pwn::windows::ctf::Remote::init() -> bool
{
    WSADATA wsaData = {0};
    auto ret        = ::WSAStartup(MAKEWORD(2, 2), &wsaData);
    if ( ret != NO_ERROR )
    {
        pwn::log::perror(L"WSAStartup()");
        return false;
    }

    if ( m_protocol == L"tcp" )
    {
        m_socket = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        // TODO: supporter d'autres proto
    }
    else
    {
        throw std::invalid_argument("m_protocol");
    }

    if ( m_socket == INVALID_SOCKET )
    {
        err(L"socket() function: %#x\n", ::WSAGetLastError());
        cleanup();
        return false;
    }

    return true;
}


auto
pwn::windows::ctf::Remote::connect() -> bool
{
    if ( !init() )
    {
        return false;
    }

    sockaddr_in sin = {0};
    sin.sin_family  = AF_INET;
    inet_pton(AF_INET, pwn::utils::to_string(m_host).c_str(), &sin.sin_addr.s_addr);
    sin.sin_port = htons(m_port);

    if ( ::connect(m_socket, (SOCKADDR*)&sin, sizeof(sin)) == SOCKET_ERROR )
    {
        err(L"connect function failed with error: %ld\n", ::WSAGetLastError());
        disconnect();
        cleanup();
        return false;
    }

    dbg(L"connected to %s:%d\n", m_host.c_str(), m_port);
    return true;
}


auto
pwn::windows::ctf::Remote::disconnect() -> bool
{
    auto res = true;

    if ( ::closesocket(m_socket) == SOCKET_ERROR )
    {
        err(L"closesocket() failed: %ld\n", ::WSAGetLastError());
        res = false;
    }

    cleanup();
    dbg(L"session to %s:%d closed\n", m_host.c_str(), m_port);
    return res;
}


auto
pwn::windows::ctf::Remote::cleanup() -> bool
{
    return ::WSACleanup() != SOCKET_ERROR;
}


auto
pwn::windows::ctf::Remote::reconnect() -> bool
{
    return disconnect() && connect();
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
        // m_hProcess = pwn::utils::GenericHandle(pi.hProcess);
        ::CloseHandle(pi.hThread);
        return true;
    }

    return false;
}
