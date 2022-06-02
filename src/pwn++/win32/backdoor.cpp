#include "backdoor.hpp"

#include <mutex>

#include "handle.hpp"
#include "pwn.hpp"
#include "utils.hpp"

using namespace pwn::utils;

typedef struct _ThreadConfig
{
    HANDLE hPipe;
    HANDLE hEvent;
} ThreadConfig;


DWORD WINAPI
HandleClientThread(LPVOID lpThreadParams)
{
    if ( lpThreadParams == nullptr )
    {
        // expected the pipe handle as parameter
        return ERROR_INVALID_PARAMETER;
    }

    ThreadConfig* cfg = reinterpret_cast<ThreadConfig*>(lpThreadParams);

    auto hPipe = pwn::utils::GenericHandle(cfg->hPipe);

    ::SetEvent(cfg->hEvent);

    while ( true )
    {
        std::unique_ptr<BYTE[]> request;
        std::unique_ptr<BYTE[]> response;

        // Wait for a command
        {
            request = std::make_unique<BYTE[]>(PWN_BACKDOOR_MAX_MESSAGE_SIZE);

            DWORD dwNumberOfByteRead;
            auto bRes =
                ::ReadFile(hPipe.get(), request.get(), PWN_BACKDOOR_MAX_MESSAGE_SIZE, &dwNumberOfByteRead, nullptr);

            if ( bRes == false )
            {
                // failed to read, todo: handle better
                pwn::log::perror(L"ReadFile()");
                break;
            }
        }

        // Parse and execute the command
        {
            // for now just ping back
            response = std::make_unique<BYTE[]>(PWN_BACKDOOR_MAX_MESSAGE_SIZE);
            ::RtlCopyMemory(response.get(), request.get(), PWN_BACKDOOR_MAX_MESSAGE_SIZE);

            // TODO
        }

        // Send the result (can be empty)
        {
            DWORD dwNumberOfByteRead;

            const bool bRes =
                ::WriteFile(hPipe.get(), response.get(), PWN_BACKDOOR_MAX_MESSAGE_SIZE, &dwNumberOfByteRead, nullptr);

            if ( bRes == false )
            {
                // failed to write, todo: handle better
                pwn::log::perror(L"WriteFile()");
                break;
            }
        }
    }

    ::FlushFileBuffers(hPipe.get());
    ::DisconnectNamedPipe(hPipe.get());

    return NO_ERROR;
}


auto
pwn::backdoor::start() -> Result<u32>
{
    DWORD dwThreadId = 0;

    auto hPipe = pwn::utils::GenericHandle(::CreateNamedPipeW(
        PWN_BACKDOOR_PIPENAME,
        PIPE_ACCESS_DUPLEX,
        PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
        PIPE_UNLIMITED_INSTANCES,
        PWN_BACKDOOR_MAX_MESSAGE_SIZE,
        PWN_BACKDOOR_MAX_MESSAGE_SIZE,
        0,
        nullptr));

    if ( !hPipe )
    {
        pwn::log::perror(L"CreateNamedPipeW()");
        return Err(ErrorType::Code::RuntimeError);
    }

    bool bIsConnected =
        ::ConnectNamedPipe(hPipe.get(), nullptr) != 0 ? true : (::GetLastError() == ERROR_PIPE_CONNECTED);

    if ( false == bIsConnected )
    {
        pwn::log::perror(L"ConnectNamedPipe()");
        return Err(ErrorType::Code::RuntimeError);
    }

    ThreadConfig cfg;

    ::DuplicateHandle(
        ::GetCurrentProcess(),
        reinterpret_cast<LPVOID>(hPipe.get()),
        ::GetCurrentProcess(),
        &cfg.hPipe,
        DUPLICATE_SAME_ACCESS,
        false,
        0);

    ::ResetEvent(cfg.hEvent);

    auto hThread = pwn::utils::GenericHandle(::CreateThread(nullptr, 0, HandleClientThread, &cfg, 0, &dwThreadId));

    if ( !hThread || (dwThreadId == 0u) )
    {
        pwn::log::perror(L"CreateThread()");
        return Err(ErrorType::Code::RuntimeError);
    }

    //
    // Wait for the thread to be ready
    //
    ::WaitForSingleObject(cfg.hEvent, INFINITE);

    //
    // Insert the TID in the global context
    //
    {
        std::lock_guard<std::mutex> lock(pwn::globals.m_config_mutex);
        globals.m_backdoor_client_tids.push_back(dwThreadId);
    }

    return Ok(dwThreadId);
}


auto
pwn::backdoor::stop() -> Result<bool>
{
    return Err(ErrorType::Code::NotImplementedError);
}
