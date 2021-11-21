#include "backdoor.hpp"

using namespace pwn::utils;






DWORD WINAPI
HandleClientThread(_In_opt_ LPVOID lpThreadParams)
{
    if (lpThreadParams == nullptr)
    {
        // expected the pipe handle as parameter
        return ERROR_INVALID_PARAMETER;
    }

    auto hPipe = pwn::utils::GenericHandle(
        reinterpret_cast<HANDLE>(lpThreadParams)
    );

    while (true)
    {
        auto request_message = std::make_unique<BYTE[]>(BACKDOOR_MAX_MESSAGE_SIZE);

        DWORD dwNumberOfByteRead;
        auto bRes = ::ReadFile(
            hPipe.get(),
            request_message.get(),
            BACKDOOR_MAX_MESSAGE_SIZE,
            &dwNumberOfByteRead,
            nullptr
        );

        if (bRes == 0)
        {
            // failed to read, todo: handle better
            break;
        }

        // ParseMessage(); // todo

        auto reply_message = std::make_unique<BYTE[]>(BACKDOOR_MAX_MESSAGE_SIZE);

        // auto reply_message = BuildReply(request_message); // todo

        bRes = ::WriteFile(
            hPipe.get(),
            reply_message.get(),
            BACKDOOR_MAX_MESSAGE_SIZE,
            &dwNumberOfByteRead,
            nullptr
        );

        if (bRes == 0)
        {
            // failed to write, todo: handle better
            break;
        }
    }

    ::FlushFileBuffers(hPipe.get());
    ::DisconnectNamedPipe(hPipe.get());

    return NO_ERROR;
}





_Success_(return ) auto pwn::backdoor::start() -> bool
{
    HANDLE hThread          = INVALID_HANDLE_VALUE;

    for (;;)
    {
        auto hPipe = ::CreateNamedPipe(
            BACKDOOR_PIPENAME,
            PIPE_ACCESS_DUPLEX,
            PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
            PIPE_UNLIMITED_INSTANCES,
            BACKDOOR_MAX_MESSAGE_SIZE,
            BACKDOOR_MAX_MESSAGE_SIZE,
            0,
            nullptr
        );

        if (hPipe == INVALID_HANDLE_VALUE)
        {
            return false;
        }

        auto is_connected = ::ConnectNamedPipe(hPipe, nullptr) != 0 ? true : (::GetLastError() == ERROR_PIPE_CONNECTED);

        if (!is_connected)
        {
            ::CloseHandle(hPipe);
            break;
        }

        DWORD dwThreadId = 0;

        auto hThread = pwn::utils::GenericHandle(
            ::CreateThread(
                nullptr,
                0,
                HandleClientThread,
                reinterpret_cast<LPVOID>(hPipe),
                0,
                &dwThreadId
            )
        );

        if (!hThread || (dwThreadId == 0u))
        {
            break;
        }

        globals.m_admin_thread_ids.push_back(dwThreadId);
    }

    return true;
}


auto
pwn::backdoor::stop() -> bool
{
    return false;
}

