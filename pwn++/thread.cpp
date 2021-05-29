#include "thread.h"

#include "handle.h"
#include "utils.h"


extern "C" NTSYSAPI NTSTATUS NtSetInformationThread(
    IN HANDLE          ThreadHandle,
    IN THREAD_INFORMATION_CLASS ThreadInformationClass,
    IN PVOID           ThreadInformation,
    IN ULONG           ThreadInformationLength
);


extern NTSYSAPI NTSTATUS NTAPI NtQueryInformationThread(
        IN HANDLE               ThreadHandle,
        IN THREAD_INFORMATION_CLASS ThreadInformationClass,
        OUT PVOID               ThreadInformation,
        IN ULONG                ThreadInformationLength,
        OUT PULONG              ReturnLength OPTIONAL
);


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



_Success_(return != nullptr)
std::unique_ptr<std::wstring> pwn::thread::get_name()
{
    // TODO
    return nullptr;
}



_Success_(return)
bool pwn::thread::set_name(_In_ DWORD dwThreadId, _In_ const std::wstring& name)
{
    auto hThread = pwn::utils::GenericHandle(
        ::OpenThread(THREAD_SET_LIMITED_INFORMATION, FALSE, dwThreadId)
    );
    if (!hThread)
        return false;

    UNICODE_STRING us;
    us.Length = name.length() & 0xffff;
    us.MaximumLength = 0xffff; // no one cares
    us.Buffer = (PWSTR)name.c_str();

    auto Status = NtSetInformationThread(
        hThread.get(), 
        ThreadNameInformation, 
        &us, 
        sizeof(UNICODE_STRING)
    );
    return NT_SUCCESS(Status);
}


_Success_(return)
bool pwn::thread::set_name(_In_ DWORD dwThreadId, _In_ const PBYTE lpBuffer, _In_ WORD wBufferLength)
{
    auto hThread = pwn::utils::GenericHandle(
        ::OpenThread(THREAD_SET_LIMITED_INFORMATION, FALSE, dwThreadId)
    );
    if (!hThread)
        return false;

    UNICODE_STRING us;
    us.Length = wBufferLength;
    us.MaximumLength = wBufferLength;
    us.Buffer = (PWSTR)lpBuffer;

    auto Status = NtSetInformationThread(
        hThread.get(),
        ThreadNameInformation,
        &us,
        sizeof(UNICODE_STRING)
    );
    return NT_SUCCESS(Status);
}
