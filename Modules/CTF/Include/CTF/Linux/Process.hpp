#pragma once


// clang-format off
#include "Common.hpp"
#include "Handle.hpp"
#include "Tube.hpp"
#include "Utils.hpp"
// clang-format on


namespace pwn::CTF
{

///
/// A Process session (pwntools-like)
///
class Process : public Net::Tube
{
public:
    ///
    ///@brief Construct a new Process object
    ///
    Process() = default;

    ///
    ///@brief Destroy the Process object
    ///
    ~Process() = default;

protected:
    ///
    ///@brief
    ///
    ///@param out
    ///@return Result<usize>
    ///
    Result<usize>
    send_internal(std::vector<u8> const& out);


    ///
    ///@brief
    ///
    ///@param size
    ///@return Result<std::vector<u8>>
    ///
    Result<std::vector<u8>>
    recv_internal(usize size = Tube::PIPE_DEFAULT_SIZE);


    ///
    ///@brief
    ///
    ///@return Result<usize>
    ///
    Result<usize>
    peek_internal();


private:
    ///
    ///@brief Create a pipes object
    ///
    ///@return true
    ///@return false
    ///
    bool
    create_pipes();


    ///
    ///@brief
    ///
    ///@return true
    ///@return false
    ///
    bool
    spawn_process();


private:
    std::wstring m_processname;
    std::wstring m_commandline;

    UniqueHandle m_hProcess;

    int m_ChildPipeStdin  = -1;
    int m_ChildPipeStdout = -1;
    int m_ParentStdin     = -1;
    int m_ParentStdout    = -1;
};


} // namespace pwn::CTF
