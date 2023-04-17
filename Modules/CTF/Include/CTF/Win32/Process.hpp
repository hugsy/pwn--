#pragma once

#include "Common.hpp"
#include "Handle.hpp"
#include "Tube.hpp"
#include "Utils.hpp"
#include "Win32/Process.hpp"


namespace pwn::CTF
{

///
///@brief A Process session
///
class Process : public Net::Tube
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
    ///@brief Get the `Process` object
    ///
    ///@return Process&
    ///
    ::Process::Process&
    Object();


protected:
    Result<usize>
    send_internal(_In_ std::vector<u8> const& out);


    Result<std::vector<u8>>
    recv_internal(_In_ usize size);


    Result<usize>
    peek_internal();


private:
    Result<bool>
    CreateInOutPipes();

    std::wstring m_CommandLine;

    ::Process::Process m_Process;

    HANDLE m_ChildPipeStdin   = INVALID_HANDLE_VALUE;
    HANDLE m_ChildPipeStdout  = INVALID_HANDLE_VALUE;
    HANDLE m_ParentPipeStdin  = INVALID_HANDLE_VALUE;
    HANDLE m_ParentPipeStdout = INVALID_HANDLE_VALUE;
};


} // namespace CTF
