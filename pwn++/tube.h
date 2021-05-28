#pragma once

#include "common.h"
#include "log.h"
#include "utils.h"

#include <string>
#include <iterator>
#include <stdexcept>
#include <queue>
#include <iostream>
#include <functional>

#include <winsock2.h>
#include <ws2tcpip.h>


#define PWN_TUBE_PIPE_DEFAULT_SIZE 1024
#define PWN_LINESEP 0x0a // '\n'


class Tube
{
public:
	/// <summary>
	/// Move data given as argument to the send buffer, tries to send. 
	/// This pure function should be defined for each new derived tube.
	/// </summary>
	PWNAPI size_t send(_In_ std::vector<BYTE> const& str);
	PWNAPI size_t send(_In_ std::string const& str);

	/// <summary>	
	/// Read bytes from the tube, moves the read bytes to the receive buffer.
	/// This pure function should be defined for each new derived tube.
	/// </summary>
	PWNAPI std::vector<BYTE> recv(_In_ size_t size);
		
	/// <summary>
	/// Send the data (as byte vector) followed by a line separator
	/// </summary>
	PWNAPI size_t sendline(_In_ std::vector<BYTE> const& data);

	/// <summary>
	/// Send the data (as str) followed by a line separator
	/// </summary>
	/// <param name="str"></param>
	/// <returns></returns>
	PWNAPI size_t sendline(_In_ std::string const& str);

	/// <summary>
	/// Read from tube until receiving a LF character, and return it.
	/// </summary>	
	PWNAPI std::vector<BYTE> recvline();
	
	/// <summary>
	/// Peek into the tube to see if any data is available.
	/// </summary>
	PWNAPI size_t peek();

	/// <summary>
	/// Basic REPL.
	/// TODO: improve
	/// </summary>
	/// <returns></returns>
	PWNAPI void interactive();



protected:
	Tube(){}
	~Tube(){}

	virtual size_t __send_internal(_In_ std::vector<BYTE> const& data) = 0;
	virtual std::vector<BYTE> __recv_internal(_In_ size_t size) = 0;
	virtual size_t __peek_internal() = 0;

	std::vector<BYTE> m_receive_buffer;
	std::vector<BYTE> m_send_buffer;
};


namespace pwn::ctf
{

#pragma comment(lib, "ws2_32.lib")

class Remote : public Tube
{
public: 
	Remote(_In_ std::wstring const& host, _In_ u16 port)
		: m_host(host), m_port(port), m_protocol(L"tcp"), m_socket(INVALID_SOCKET)
	{
		if (!connect())
		{
			throw std::runtime_error("connection to host failed");
		}
	}

	~Remote()
	{
		disconnect();
	}


protected:
	size_t __send_internal(_In_ std::vector<BYTE> const& out) override
	{
		auto res = ::send(
			m_socket,
			reinterpret_cast<const char*>(&out[0]),
			out.size() & 0xffff,
			0
		);
		if (res == SOCKET_ERROR)
		{
			err(L"send() function: %x\n", ::WSAGetLastError());
			disconnect();
			return 0;
		}

		dbg(L"sent %d bytes\n", out.size());
		return out.size();
	}


	std::vector<BYTE> __recv_internal(_In_ size_t size = PWN_TUBE_PIPE_DEFAULT_SIZE) override
	{
		std::vector<BYTE> in;
		size_t idx = 0;

		size = min(size, PWN_TUBE_PIPE_DEFAULT_SIZE);

		// try to read from the cache
		if (!m_receive_buffer.empty())
		{
			auto sz = min(size, m_receive_buffer.size());
			std::copy(
				m_receive_buffer.begin(),
				m_receive_buffer.begin() + sz,
				std::back_inserter(in)
			);

			m_receive_buffer.erase(
				m_receive_buffer.begin() ,
				m_receive_buffer.begin() + sz
			);

			// check if the buffer is already full with data from cache
			if (in.size() >= size)
			{
				dbg(L"recv2 %d bytes\n", in.size());
				return in;
			}

			// otherwise, read from network
			size -= sz;
			idx = sz;
		}

		in.reserve(in.size() + size);

		auto res = ::recv(m_socket, reinterpret_cast<char*>(&in[idx]), (u32)size, 0);
		if (res == SOCKET_ERROR)
		{
			pwn::log::perror(L"recv()");
			throw std::runtime_error("::recv() failed");
		}
		else
		{
			size_t sz = in.size() + res;
			in.resize(sz);
			dbg(L"recv %d bytes\n", sz);
		}
		return in;
	}

	size_t __peek_internal() override
	{
		auto buf = std::make_unique<BYTE[]>(PWN_TUBE_PIPE_DEFAULT_SIZE);
		auto res = ::recv(m_socket, reinterpret_cast<char*>(buf.get()), PWN_TUBE_PIPE_DEFAULT_SIZE, MSG_PEEK);
		if (res == SOCKET_ERROR)
		{
			pwn::log::perror(L"recv()");
			throw std::runtime_error("::recv() failed");
		}

		return res;
	}



private:
	bool init()
	{
		WSADATA wsaData = { 0 };
		auto ret = ::WSAStartup(MAKEWORD(2, 2), &wsaData);
		if (ret != NO_ERROR) 
		{
			pwn::log::perror(L"WSAStartup()");
			return false;
		}

		if (m_protocol == L"tcp")
			m_socket = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
			// TODO: supporter d'autres proto
		else
			throw std::invalid_argument("m_protocol");

		if (m_socket == INVALID_SOCKET) 
		{
			err(L"socket() function: %ld\n", ::WSAGetLastError());
			cleanup();
			return false;
		}

		return true;
	}


	bool connect()
	{
		if (!init()) 
			return false;

		sockaddr_in sin = { 0 };
		sin.sin_family = AF_INET;
		inet_pton(AF_INET, pwn::utils::widestring_to_string(m_host).c_str(), &sin.sin_addr.s_addr);
		sin.sin_port = htons(m_port);

		if (::connect(m_socket, (SOCKADDR*)&sin, sizeof(sin)) == SOCKET_ERROR) 
		{
			err(L"connect function failed with error: %ld\n", ::WSAGetLastError());
			disconnect();
			cleanup();
			return false;
		}

		dbg(L"connected to %s:%d\n", m_host.c_str(), m_port);
		return true;
	}


	bool disconnect()
	{
		auto res = true;

		if (::closesocket(m_socket) == SOCKET_ERROR)
		{
			err(L"closesocket() failed: %ld\n", WSAGetLastError());
			res = false;
		}

		cleanup();
		dbg(L"session to %s:%d closed\n", m_host.c_str(), m_port);
		return res;
	}


	bool cleanup()
	{
		return ::WSACleanup() != SOCKET_ERROR;
	}


	bool reconnect() 
	{ 
		return disconnect() && connect(); 
	}


	std::wstring m_host;
	std::wstring m_protocol;
	u16 m_port;
	SOCKET m_socket;
};




}