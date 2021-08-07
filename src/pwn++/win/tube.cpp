#include "tube.hpp"


auto Tube::send(_In_ std::vector<BYTE> const& data) -> size_t
{
	return __send_internal(data);
}


auto Tube::send(_In_ std::string const& str) -> size_t
{
	return __send_internal(pwn::utils::string_to_bytes(str));
}


auto Tube::recv(_In_ size_t size) -> std::vector<BYTE>
{
	return __recv_internal(size);
}


auto Tube::sendline(_In_ std::vector<BYTE> const& data) -> size_t
{
	auto send_data(data);
	send_data.push_back(PWN_LINESEP);
	return send(send_data);
}


auto Tube::sendline(_In_ std::string const& str) -> size_t
{
	return sendline(pwn::utils::string_to_bytes(str));
}


auto Tube::recvuntil(_In_ std::vector<BYTE> const& pattern) -> std::vector<BYTE>
{
	size_t idx = 0;
	std::vector<BYTE> in;

	while (true)
	{
		// append new data received from the pipe
		{
			auto in2 = recv(PWN_TUBE_PIPE_DEFAULT_SIZE);
			if (in2.empty()) {
				continue;
}
			std::copy(in2.begin(), in2.end(), std::back_inserter(in));
		}

		// look for the pattern
		if (std::find_if(
			in.begin(),
			in.end(),
			[&idx,&pattern, &in](BYTE const& x) {
				idx++;
				auto i = idx;
				auto sz = pattern.size();

				if (i < sz) {
					return false;
}

				for (size_t j = 0; j < sz; j++)
				{
					if (pattern.at(j) != in.at( (i-sz) + j)) {
						return false;
}
				}

				return true;
			}
		) != in.end())
		{
			// line separator found, copy the rest of the buffer to the queue
			std::copy(
				in.begin() + idx,
				in.end(),
				std::back_inserter(m_receive_buffer)
			);

			in.erase(
				in.begin() + idx,
				in.end()
			);

			return in;
		}
	}
}


auto Tube::recvuntil(_In_ std::string const& pattern) -> std::vector<BYTE>
{
	return recvuntil(pwn::utils::string_to_bytes(pattern));
}


auto Tube::recvline() -> std::vector<BYTE>
{
	return recvuntil(std::vector<BYTE>{PWN_LINESEP});
}


auto Tube::sendafter(_In_ std::vector<BYTE> const& pattern, _In_ std::vector<BYTE> const& data) -> size_t
{
	recvuntil(pattern);
	return send(data);
}


auto Tube::sendafter(_In_ std::string const& pattern, _In_ std::string const& data) -> size_t
{
	recvuntil(pattern);
	return send(data);
}


auto Tube::sendlineafter(_In_ std::vector<BYTE> const& pattern, _In_ std::vector<BYTE> const& data) -> size_t
{
	recvuntil(pattern);
	return sendline(data);
}


auto Tube::sendlineafter(_In_ std::string const& pattern, _In_ std::string const& data) -> size_t
{
	recvuntil(pattern);
	return sendline(data);
}


auto Tube::peek() -> size_t
{
	return __peek_internal();
}


static bool __bReplLoop = false;


_Success_(return)
static BOOL WINAPI __pwn_interactive_repl_sighandler(_In_ DWORD signum)
{
	switch (signum)
	{
		case CTRL_C_EVENT:
			dbg(L"Stopping interactive mode...\n");
			__bReplLoop = false;
			::ExitProcess(0);
			break;

		default:
			break;
	}

	return TRUE;
}



void Tube::interactive()
{
	__bReplLoop = true;

	::SetConsoleCtrlHandler(__pwn_interactive_repl_sighandler, 1);

	ok(L"Entering interactive mode...\n");

	// the `remote` thread reads and prints received data
	std::thread remote([&]() {
		using namespace std::literals::chrono_literals;

		while (__bReplLoop)
		{
			while (true)
			{
				try
				{
					auto in = recv(PWN_TUBE_PIPE_DEFAULT_SIZE);
					std::cout << std::string(in.begin(), in.end());

					if (in.size() < PWN_TUBE_PIPE_DEFAULT_SIZE) {
						break;
}

					std::this_thread::sleep_for(0.1s); // for debug, remove later
				}
				catch (...)
				{
					break;
				}
			}
		}
	});

	while (__bReplLoop)
	{
		std::string cmd;
		std::cout << PWN_INTERACTIVE_PROMPT;
		std::getline(std::cin, cmd);

		if (cmd == "quit")
		{
			__bReplLoop = false;
			break;
		}

		sendline(cmd);
	}

	remote.join();

	::SetConsoleCtrlHandler(nullptr, 1);

	ok(L"Leaving interactive mode...\n");
}