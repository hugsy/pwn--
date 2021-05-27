#include "tube.h"


size_t Tube::send(_In_ std::vector<BYTE> const& data)
{
	return __send_internal(data);
}


size_t Tube::send(_In_ std::string const& str)
{
	return __send_internal(pwn::utils::string_to_bytes(str));
}


std::vector<BYTE> Tube::recv(_In_ size_t size)
{
	return __recv_internal(size);
}


size_t Tube::sendline(_In_ std::vector<BYTE> const& data)
{
	auto send_data(data);
	send_data.push_back(PWN_LINESEP);
	return send(send_data);
}


size_t Tube::sendline(_In_ std::string const& str)
{
	return sendline(pwn::utils::string_to_bytes(str));
}


std::vector<BYTE> Tube::recvline()
{
	size_t idx = 0;
	std::vector<BYTE> in;

	while (true)
	{
		{
			auto in2 = recv(PWN_TUBE_PIPE_DEFAULT_SIZE);
			if (in2.empty()) 
				return {};
			in.insert(in.begin(), in2.begin(), in2.end());
		}

		if (std::find_if(
			in.begin(),
			in.end(),
			[&idx](BYTE const& x) { idx++; return x == PWN_LINESEP; }
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


void Tube::interactive()
{
	bool bDoLoop = true;

	while (bDoLoop)
	{
		std::string cmd;
		std::cout << ">>> ";
		std::cin >> cmd;

		send(cmd);
		std::cout << "<<< " << std::endl;
		pwn::utils::hexdump(recvline());
	}
}