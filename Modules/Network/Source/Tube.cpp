#include "Tube.hpp"

#include <algorithm>
#include <chrono>
#include <iostream>
#include <iterator>
#include <thread>

#include "Context.hpp"
#include "Log.hpp"
#include "Utils.hpp"

extern struct GlobalContext Context;

namespace pwn::Net
{
Result<usize>
Tube::send(_In_ std::vector<u8> const& data)
{
    return send_internal(data);
}


Result<usize>
Tube::send(_In_ std::string const& str)
{
    return send_internal(Utils::StringLib::To<std::vector<u8>>(str));
}


Result<std::vector<u8>>
Tube::recv(_In_ usize size)
{
    return recv_internal(size);
}


Result<usize>
Tube::sendline(_In_ std::vector<u8> const& data)
{
    std::vector<u8> send_data(data);
    send_data.push_back(Tube::LINE_SEPARATOR);
    return send(send_data);
}


Result<usize>
Tube::sendline(_In_ std::string const& str)
{
    return sendline(Utils::StringLib::To<std::vector<u8>>(str));
}


Result<std::vector<u8>>
Tube::recvuntil(_In_ std::vector<u8> const& pattern)
{
    size_t idx = 0;
    std::vector<u8> in;

    while ( true )
    {
        //
        // append new data received from the pipe
        //
        {
            auto res = recv(Tube::PIPE_DEFAULT_SIZE);
            if ( Failed(res) )
            {
                return Err(res.error());
            }

            std::vector<u8> const chunk = Value(res);
            if ( chunk.empty() )
            {
                continue;
            }
            std::copy(chunk.cbegin(), chunk.cend(), std::back_inserter(in));
        }

        //
        // look for the pattern
        //
        auto ContainsSubVector = [&in, &pattern]() -> bool
        {
            return std::search(in.cbegin(), in.cend(), pattern.cbegin(), pattern.cend()) != in.end();
        };

        if ( ContainsSubVector() )
        {
            //
            // line separator found, copy the rest of the buffer to the queue
            //
            std::copy(in.begin(), in.end(), std::back_inserter(m_receive_buffer));
            dbg("Received {} bytes", in.size());
            return Ok(in);
        }
    }

    //
    // The loop was exited without the pattern being found, return an error
    //
    return Err(Error::NotFound);
}


Result<std::vector<u8>>
Tube::recvuntil(_In_ std::string const& pattern)
{
    return recvuntil(Utils::StringLib::To<std::vector<u8>>(pattern));
}


Result<std::vector<u8>>
Tube::recvline()
{
    return recvuntil(std::vector<u8> {Tube::LINE_SEPARATOR});
}


Result<usize>
Tube::sendafter(_In_ std::vector<u8> const& pattern, _In_ std::vector<u8> const& data)
{
    recvuntil(pattern);
    return send(data);
}


Result<usize>
Tube::sendafter(_In_ std::string const& pattern, _In_ std::string const& data)
{
    recvuntil(pattern);
    return send(data);
}


Result<usize>
Tube::sendlineafter(_In_ std::vector<u8> const& pattern, _In_ std::vector<u8> const& data)
{
    recvuntil(pattern);
    return sendline(data);
}


Result<usize>
Tube::sendlineafter(_In_ std::string const& pattern, _In_ std::string const& data)
{
    recvuntil(pattern);
    return sendline(data);
}


Result<usize>
Tube::peek()
{
    return peek_internal();
}


static bool __bReplLoop = false;


#ifdef PWN_BUILD_FOR_WINDOWS
_Success_(return)
static BOOL WINAPI
__pwn_interactive_repl_sighandler(_In_ DWORD signum)
{
    switch ( signum )
    {
    case CTRL_C_EVENT:
        dbg("Stopping interactive mode...\n");
        __bReplLoop = false;
        ::ExitProcess(0);
        break;

    default:
        break;
    }

    return TRUE;
}
#endif


void
Tube::interactive()
{
    __bReplLoop = true;

#ifdef PWN_BUILD_FOR_WINDOWS
    ::SetConsoleCtrlHandler(__pwn_interactive_repl_sighandler, 1);
#endif

    ok(L"Entering interactive mode...");

    // the `remote` thread reads and prints received data
    std::thread remote(
        [&]()
        {
            while ( __bReplLoop )
            {
                while ( true )
                {
                    auto res = recv(Tube::PIPE_DEFAULT_SIZE);
                    if ( Failed(res) )
                    {
                        __bReplLoop = false;
                        break;
                    }

                    std::vector<u8> const& raw_input = Value(res);
                    auto input                       = std::string(raw_input.begin(), raw_input.end());

                    {
                        std::lock_guard<std::mutex> guard(Context.m_ConsoleMutex);
                        std::cout << input << std::flush;
                    }

                    if ( raw_input.size() < Tube::PIPE_DEFAULT_SIZE )
                    {
                        break;
                    }

                    Utils::Sleep(0.1s); // for debug, remove later
                }
            }
        });

    while ( __bReplLoop )
    {
        {
            std::lock_guard<std::mutex> guard(Context.m_ConsoleMutex);
            std::cout << Tube::INTERACTIVE_PROMPT;
            std::cout.flush();
        }

        std::string cmd;
        std::getline(std::cin, cmd);
        if ( cmd == "quit" )
        {
            __bReplLoop = false;
            break;
        }

        sendline(cmd);
    }

    remote.join();

#ifdef PWN_BUILD_FOR_WINDOWS
    ::SetConsoleCtrlHandler(nullptr, 1);
#endif

    ok("Leaving interactive mode...");
}
} // namespace pwn::Net
