#include "backdoor.hpp"

#include <mutex>

#include "handle.hpp"
#include "pwn.hpp"
#include "utils.hpp"

using namespace pwn::utils;

namespace pwn::backdoor
{

namespace
{

auto
OpenPipe() -> Result<HANDLE>
{
    auto hPipe = ::CreateNamedPipeW(
        // PWN_BACKDOOR_PIPENAME,
        L"\\\\.\\pipe\\mynamedpipe",
        PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
        PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
        PIPE_UNLIMITED_INSTANCES,
        PWN_BACKDOOR_MAX_MESSAGE_SIZE,
        PWN_BACKDOOR_MAX_MESSAGE_SIZE,
        0,
        nullptr);

    if ( INVALID_HANDLE_VALUE == hPipe )
    {
        pwn::log::perror(L"CreateNamedPipeW()");
        return Err(ErrorType::Code::RuntimeError);
    }

    return Ok(hPipe);
}


auto
WaitNextConnectionAsync(const HANDLE hPipe, LPOVERLAPPED oConnect) -> Result<bool>
{
    bool bIsPending = false;

    dbg(L"Waiting for connection");
    const bool bIsConnected = ::ConnectNamedPipe(hPipe, oConnect);

    if ( bIsConnected )
    {
        pwn::log::perror(L"ConnectNamedPipe()");
        return Err(ErrorType::Code::ConnectionError);
    }

    switch ( ::GetLastError() )
    {
    case ERROR_IO_PENDING:
        bIsPending = true;
        break;
    case ERROR_PIPE_CONNECTED:
        ::SetEvent(oConnect->hEvent);
        bIsPending = false;
        break;
    default:
        pwn::log::perror(L"ConnectNamedPipe()");
        return Err(ErrorType::Code::ConnectionError);
    }

    return Ok(bIsPending);
}


DWORD WINAPI
HandleClientThread(const LPVOID lpThreadParams)
{
    if ( lpThreadParams == nullptr )
    {
        // expected the pipe handle as parameter
        return ERROR_INVALID_PARAMETER;
    }

    const auto cfg   = reinterpret_cast<pwn::backdoor::ThreadConfig*>(lpThreadParams);
    const auto hPipe = pwn::utils::GenericHandle(cfg->hPipe);
    cfg->SetState(ThreadState::ReadyToRead);

    while ( cfg->State != ThreadState::Stopped )
    {
        DWORD size = 0;

        const DWORD Status = ::WaitForSingleObject(cfg->hStateChangeEvent, 0);
        switch ( Status )
        {
        // We expect a success, any other case should stop the execution
        case WAIT_OBJECT_0:
            break;

        default:
            cfg->SetState(ThreadState::Stopping);
            pwn::log::perror(L"WaitForMultipleObjects");
            break;
        }

        if ( cfg->State == ThreadState::Stopping )
        {
            dbg(L"Termination event received");
            ::FlushFileBuffers(hPipe.get());
            // todo: also wait for last io
            cfg->SetState(ThreadState::Stopped);
            continue;
        }

        //
        // Wait for a command
        //
        if ( cfg->State == ThreadState::ReadyToRead )
        {
            cfg->request = std::make_unique<u8[]>(PWN_BACKDOOR_MAX_MESSAGE_SIZE);
            ::RtlSecureZeroMemory(cfg->request.get(), PWN_BACKDOOR_MAX_MESSAGE_SIZE);

            DWORD dwNumberOfByteRead;
            auto bRes = ::ReadFile(
                hPipe.get(),
                cfg->request.get(),
                PWN_BACKDOOR_MAX_MESSAGE_SIZE,
                &dwNumberOfByteRead,
                &cfg->oReadWrite);

            if ( bRes )
            {
                cfg->request_size = dwNumberOfByteRead;
                cfg->SetState(ThreadState::ReadFinished);
            }
            else
            {
                switch ( ::GetLastError() )
                {
                case ERROR_IO_PENDING:
                    cfg->SetState(ThreadState::ReadInProgress);
                    break;
                default:
                    pwn::log::perror(L"ReadFile()");
                    cfg->SetState(ThreadState::Stopping);
                }
            }
            continue;
        }

        //
        // Finish overlapped read IO
        //
        if ( cfg->State == ThreadState::ReadInProgress )
        {
            if ( ::GetOverlappedResult(hPipe.get(), &cfg->oReadWrite, &size, true) )
            {
                cfg->request_size = size;
                cfg->SetState(ThreadState::ReadFinished);
            }
            else
            {
                switch ( ::GetLastError() )
                {
                case ERROR_IO_PENDING:
                    cfg->SetState(ThreadState::ReadInProgress);
                    break;
                default:
                    pwn::log::perror(L"GetOverlappedResult()");
                    cfg->SetState(ThreadState::Stopping);
                }
            }
            continue;
        }

        //
        // Parse and execute the command
        //
        if ( cfg->State == ThreadState::ReadFinished )
        {
            // for now just ping back
            cfg->response_size = cfg->request_size;
            cfg->response      = std::make_unique<u8[]>(cfg->response_size);
            ::RtlCopyMemory(cfg->response.get(), cfg->request.get(), cfg->response_size);

            DWORD dwNumberOfByteRead;

            // todo: for now, it's ok to make write blocking
            const bool bRes =
                ::WriteFile(hPipe.get(), cfg->response.get(), cfg->response_size, &dwNumberOfByteRead, nullptr);

            if ( bRes == false )
            {
                pwn::log::perror(L"WriteFile()");
                cfg->SetState(ThreadState::Stopping);
            }
            else
            {
                cfg->SetState(ThreadState::ReadyToRead);
            }
            continue;
        }
    }

    dbg(L"Disconnecting session TID={}", cfg->Tid);
    ::DisconnectNamedPipe(hPipe.get());

    return NO_ERROR;
}


auto
StartClientSession(const HANDLE hPipe) -> Result<std::shared_ptr<ThreadConfig>>
{
    dbg(L"New connection, initalizing new client");
    DWORD dwThreadId = 0;

    auto client     = std::make_shared<ThreadConfig>();
    client->hPipe   = hPipe;
    client->hThread = ::CreateThread(nullptr, 0, HandleClientThread, client.get(), 0, &dwThreadId);

    if ( client->hThread == INVALID_HANDLE_VALUE || (dwThreadId == 0u) )
    {
        pwn::log::perror(L"CreateThread()");
        return Err(ErrorType::Code::RuntimeError);
    }

    client->Tid = dwThreadId;

    dbg(L"Started client thread TID={}", client->Tid);
    return Ok(client);
}


auto
AllowNextClient() -> Result<bool>
{
    HANDLE hPipe = INVALID_HANDLE_VALUE;

    // Prepare the pip
    {
        const auto res = OpenPipe();
        if ( Failed(res) )
        {
            return Error(res);
        }

        hPipe = Value(res);
    }


    // Wait for the next client on the pipe
    {
        OVERLAPPED oConnect;
        ::RtlSecureZeroMemory(&oConnect, sizeof(OVERLAPPED));
        oConnect.hEvent = ::CreateEvent(nullptr, false, false, nullptr);

        const auto res = WaitNextConnectionAsync(hPipe, &oConnect);
        if ( Failed(res) )
        {
            return res;
        }

        const bool bIsPending = Value(res);

        while ( true )
        {
            const DWORD dwWait = ::WaitForSingleObjectEx(oConnect.hEvent, INFINITE, true);
            switch ( dwWait )
            {
            case WAIT_IO_COMPLETION:
                // Completion is pending, wait for it to finish
                break;
            case 0:
                if ( bIsPending )
                {
                    // collect the result of the connect operation.

                    DWORD dwTransferedBytes;
                    ::GetOverlappedResult(hPipe, &oConnect, &dwTransferedBytes, false);
                }

                //
                // the connection is ready, start the handling thread
                //
                {
                    auto const res = StartClientSession(hPipe);
                    if ( Failed(res) )
                    {
                        err(L"Failed to initialize the new client");
                        return Error(res);
                    }

                    auto client = Value(res);

                    //
                    // Insert the client configuration in the global context
                    //
                    {
                        std::lock_guard<std::mutex> lock(pwn::globals.m_config_mutex);
                        globals.m_backdoor_clients.push_back(client);
                    }

                    return Ok(true);
                }

            default:
                return Ok(false);
            }

            break;
        }
    }

    return Err(ErrorType::Code::GenericError);
}

} // namespace

auto
start() -> Result<bool>
{
    globals.m_backdoor_thread = std::jthread::jthread(
        []
        {
            while ( true )
            {
                AllowNextClient();
            }
        });

    return Ok(true);
}


auto
stop() -> Result<bool>
{
    std::vector<HANDLE> handles;
    std::lock_guard<std::mutex> lock(pwn::globals.m_config_mutex);
    const usize sz = globals.m_backdoor_clients.size();

    for ( auto const& client : globals.m_backdoor_clients )
    {
        dbg(L"Stopping client {}", client->Tid);
        client->SetState(ThreadState::Stopped);
        handles.push_back(client->hThread);
    }

    ::WaitForMultipleObjects(sz, handles.data(), true, INFINITE);

    return Ok(true);
}

} // namespace pwn::backdoor
