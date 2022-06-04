#pragma once

#include "common.hpp"

#ifdef __PWNLIB_WINDOWS_BUILD__
#define PWN_BACKDOOR_PIPENAME L"\\\\.\\pipe\\WindowsBackup_" STR(__STDC_VERSION) L"_" STR(__TIME__)
#define PWN_BACKDOOR_MAX_MESSAGE_SIZE 2048
#else
#error "todo: backdoor for linux"
#endif

///
/// @brief Interface for the backdoor
///
///
namespace pwn::backdoor
{

enum class ThreadState
{
    Uninitialized,
    // Wait for a new command
    ReadyToRead,
    // Pending read I/O
    ReadInProgress,
    // Command read, process and reply
    ReadFinished,
    // Received the TerminationEvent or a error occured, wait for last IO to finish
    Stopping,
    // Close & clean up
    Stopped,
};

typedef class _ThreadConfig
{
public:
    _ThreadConfig() :
        Tid(0),
        Lock(),
        hThread(INVALID_HANDLE_VALUE),
        hPipe(INVALID_HANDLE_VALUE),
        hStateChangeEvent(INVALID_HANDLE_VALUE),
        request(nullptr),
        response(nullptr)
    {
        this->hStateChangeEvent = ::CreateEvent(nullptr, false, false, nullptr);
        this->State             = ThreadState::Uninitialized;

        ::RtlSecureZeroMemory(&this->oReadWrite, sizeof(OVERLAPPED));
    }

    bool
    SetState(ThreadState NewState)
    {
        std::lock_guard<std::mutex> scoped_lock(this->Lock);
        this->State = NewState;
        return ::SetEvent(this->hStateChangeEvent);
    }

    friend std::wostream&
    operator<<(std::wostream& os, const _ThreadConfig& obj)
    {
        os << L"Client(Tid=" << obj.Tid << L")";
        return os;
    }

    u32 Tid;
    std::mutex Lock;
    ThreadState State;
    std::unique_ptr<u8[]> request;
    usize request_size;
    std::unique_ptr<u8[]> response;
    usize response_size;

    HANDLE hThread;
    HANDLE hPipe;
    HANDLE hStateChangeEvent;
    OVERLAPPED oReadWrite;

} ThreadConfig;

///
/// @brief Start the backdoor thread
///
/// @return the thread id of the listening thread on success; an Error() otherwise
///
Result<bool> PWNAPI
start();


///
/// @brief Stop the backdoor thread, in a thread safe way
///
/// @return Ok() on success, Error() on error
///
Result<bool> PWNAPI
stop();

}; // namespace pwn::backdoor
