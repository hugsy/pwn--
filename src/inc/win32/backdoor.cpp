#include "backdoor.hpp"

#include <iostream>
#include <mutex>
#include <sstream>

#include "handle.hpp"
#include "pwn.hpp"
#include "utils.hpp"

using namespace pwn::utils;


namespace pwn::backdoor
{

///
/// @brief Where the LUA VM lives
///
namespace lua
{

//
// Function and module registration arrays
//
static const luaL_Reg pwn_module_functions[]         = {{"version", pwn_version}, {nullptr, nullptr}};
static const luaL_Reg pwn_utils_module_functions[]   = {{"hexdump", pwn_utils_hexdump}, {nullptr, nullptr}};
static const luaL_Reg pwn_process_module_functions[] = {{"pid", pwn_process_pid}, {nullptr, nullptr}};


///
/// @brief LUA VM initialization function
///
lua_State*
init()
{
    lua_State* LuaVm = nullptr;

    dbg(L"[backdoor] Initializing Lua VM");

    //
    // Initialize the VM
    //
    LuaVm = luaL_newstate();

    //
    // Load some basic modules
    //
#if LUA_VERSION_NUM >= 501
    luaL_openlibs(LuaVm);
#else
    luaopen_base(LuaVm);
    luaopen_table(LuaVm);
    luaopen_io(LuaVm);
    luaopen_string(LuaVm);
    luaopen_math(LuaVm);
#endif

    //
    // Create the `pwn` module
    //
    luaL_newlib(LuaVm, pwn_module_functions);

#define REGISTER_LUA_SUBMODULE(name)                                                                                   \
    {                                                                                                                  \
        luaL_newlib(LuaVm, pwn_##name##_module_functions);                                                             \
        lua_setfield(LuaVm, -2, STR(name));                                                                            \
    }

    REGISTER_LUA_SUBMODULE(utils);
    REGISTER_LUA_SUBMODULE(process);

#undef REGISTER_LUA_SUBMODULE

    //
    // Expose the `pwn` root module
    //
    lua_setglobal(LuaVm, "pwn");

    return LuaVm;
} // namespace lua


///
/// @brief LUA VM deallocation function
///
void
close(lua_State* LuaVm)
{
    if ( LuaVm )
    {
        dbg(L"[backdoor] Deinitializing Lua VM");
        lua_close(LuaVm);
        LuaVm = nullptr;
    }
    else
    {
        warn(L"[backdoor] Lua VM is not initialized");
    }
}


///
/// @brief
///
/// @param cfg
/// @param os
/// @param index
///
void
return_values(ThreadConfig* cfg, std::stringstream& os, const usize index)
{
    lua_State* LuaVm = cfg->pLuaVm;

    if ( index == 0 )
        return;

    switch ( lua_type(LuaVm, -1) )
    {
    case LUA_TNIL:
        os << "(nil)";
        break;

    case LUA_TBOOLEAN:
        os << (lua_toboolean(LuaVm, -1) == 1) ? "true" : "false";
        break;

    case LUA_TSTRING:
        os << lua_tostring(LuaVm, -1);
        break;

    case LUA_TNUMBER:
        // TODO also support long, double, etc.
        os << std::to_string(lua_tointeger(LuaVm, -1));
        break;

    default:
        os << "<unknown>";
    }
    lua_pop(LuaVm, 1);

    os << "\n";

    return return_values(cfg, os, index - 1);
}


///
/// @brief
///
/// @param cfg
/// @return Result<std::string const>
///
auto
execute(ThreadConfig* cfg) -> Result<std::string const>
{
    std::stringstream os;

    lua_State* LuaVm = cfg->pLuaVm;
    if ( !LuaVm )
    {
        err(L"The VM is not ready");
        return Err(ErrorCode::VmNotInitialized);
    }

    const usize initial_stack_size = lua_gettop(LuaVm);
    const std::string name         = std::format("backdoor-command-{}", cfg->command_number++);
    const std::string request      = std::string((const char*)cfg->request.get(), cfg->request_size);

    if ( request == "exit" )
    {
        return Err(ErrorCode::TerminationError);
    }

    auto LuaRc = luaL_loadbuffer(LuaVm, request.c_str(), request.size(), name.c_str());
    if ( LuaRc )
    {
        std::string response = lua_tostring(LuaVm, -1);
        lua_pop(LuaVm, 1);
        return Ok(response);
    }

    lua_pcall(LuaVm, 0, LUA_MULTRET, 0);
    const usize new_stack_size = lua_gettop(LuaVm);
    const usize nb_retvalues   = (new_stack_size - initial_stack_size);
    return_values(cfg, os, nb_retvalues);

    return Ok(os.str());
}


//
// Module `pwn` function definitions below
//

int
pwn_version(lua_State* l)
{
    std::string version = pwn::utils::to_string(pwn::version());
    lua_pushstring(l, version.c_str());
    return 1;
}


int
pwn_utils_hexdump(lua_State* l)
{
    double d = luaL_checknumber(l, 1);
    lua_pushnil(l);
    return 1;
}


int
pwn_process_pid(lua_State* l)
{
    lua_pushinteger(l, pwn::windows::process::pid());
    return 1;
}
} // namespace lua

namespace
{

auto
OpenPipe() -> Result<HANDLE>
{
    auto hPipe = ::CreateNamedPipeW(
        PWN_BACKDOOR_PIPENAME,
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
        return Err(ErrorCode::RuntimeError);
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
        return Err(ErrorCode::ConnectionError);
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
        return Err(ErrorCode::ConnectionError);
    }

    return Ok(bIsPending);
}


///
/// @brief Thread routine for each new client to the pipe
///
/// @param lpThreadParams
/// @return DWORD
///
DWORD WINAPI
HandleClientThread(const LPVOID lpThreadParams)
{
    if ( lpThreadParams == nullptr )
    {
        // expected the pipe handle as parameter
        return ERROR_INVALID_PARAMETER;
    }

    const auto cfg   = reinterpret_cast<pwn::backdoor::ThreadConfig*>(lpThreadParams);
    const auto hPipe = pwn::UniqueHandle(cfg->hPipe);
    cfg->pLuaVm      = lua::init();
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
        // Input read is done, process the command and send back the result
        //
        if ( cfg->State == ThreadState::ReadFinished )
        {
            DWORD dwNumberOfByteRead = 0;

            auto res = lua::execute(cfg);
            if ( Failed(res) )
            {
                if ( Error(res).code == ErrorCode::TerminationError )
                    warn(L"Termination requested by user");
                cfg->SetState(ThreadState::Stopping);
                continue;
            }

            std::string response = Value(res);
            cfg->response_size   = response.size();
            cfg->response        = std::make_unique<u8[]>(cfg->response_size);

            ::RtlCopyMemory(cfg->response.get(), response.c_str(), cfg->response_size);

            // TODO: for now, it's ok to make write blocking
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

            ::RtlSecureZeroMemory(cfg->response.get(), cfg->response_size);
            continue;
        }
    }

    dbg(L"Disconnecting session TID={}", cfg->Tid);
    ::DisconnectNamedPipe(hPipe.get());

    lua::close(cfg->pLuaVm);
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
        return Err(ErrorCode::RuntimeError);
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

    return Err(ErrorCode::GenericError);
}


} // namespace

auto
start() -> Result<bool>
{
    dbg(L"Listening for connection on '{}'", PWN_BACKDOOR_PIPENAME);

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
