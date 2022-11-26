#pragma once

#include "common.hpp"
#include "handle.hpp"
#include "tube.hpp"
#include "utils.hpp"
#include "win32/process.hpp"


namespace pwn::windows::ctf
{

///
///@brief A Process session
///
class Process : public Tube
{
public:
    ///
    ///@brief Construct a new CTF Process object
    ///
    ///@param CommandLine
    ///
    Process(std::wstring_view const& CommandLine);


    ///
    ///@brief Destroy the CTF Process object
    ///
    ~Process();


    ///
    ///@brief Spawn the process
    ///
    ///@param StartSuspended
    ///@return Result<bool>
    ///
    Result<bool>
    Spawn(bool StartSuspended = false);


    ///
    ///@brief Get the `pwn::windows::Process` object
    ///
    ///@return pwn::windows::Process&
    ///
    pwn::windows::Process&
    Object();


protected:
    Result<usize>
    send_internal(_In_ std::vector<u8> const& out);


    Result<std::vector<u8>>
    recv_internal(_In_ size_t size);


    Result<usize>
    peek_internal();


private:
    Result<bool>
    CreateInOutPipes();

    std::wstring m_CommandLine;

    pwn::windows::Process m_Process;

    HANDLE m_ChildPipeStdin   = INVALID_HANDLE_VALUE;
    HANDLE m_ChildPipeStdout  = INVALID_HANDLE_VALUE;
    HANDLE m_ParentPipeStdin  = INVALID_HANDLE_VALUE;
    HANDLE m_ParentPipeStdout = INVALID_HANDLE_VALUE;
};


} // namespace pwn::windows::ctf
