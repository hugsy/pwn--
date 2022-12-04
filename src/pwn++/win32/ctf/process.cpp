// clang-format off
#include "win32/ctf/process.hpp"

#include <functional>
#include <iostream>
#include <iterator>
#include <queue>
#include <stdexcept>
#include <string>
#include <thread>
#include <utility>

#include "pwn.hpp"
#include "handle.hpp"
#include "log.hpp"
#include "tube.hpp"
#include "utils.hpp"
// clang-format on


///
/// @file Process
///


pwn::windows::ctf::Process::Process(std::wstring_view const& CommandLine) : m_CommandLine(CommandLine)
{
}


pwn::windows::ctf::Process::~Process()
{
}


Result<usize>
pwn::windows::ctf::Process::send_internal(_In_ std::vector<u8> const& out)
{
    DWORD dwWritten = 0;

    auto bSuccess = ::WriteFile(m_ParentPipeStdin, &out[0], out.size() & 0xffffffff, &dwWritten, nullptr);
    if ( bSuccess == FALSE )
    {
        return Err(ErrorCode::ExternalApiCallFailed);
    }

    return Ok(dwWritten);
}


Result<std::vector<u8>>
pwn::windows::ctf::Process::recv_internal(_In_ size_t size)
{
    DWORD dwRead = 0;
    std::vector<u8> out;

    size = std::min(size, Tube::PIPE_DEFAULT_SIZE) & 0xffffffff;
    out.clear();
    out.resize(size);

    auto bSuccess = ::ReadFile(m_ParentPipeStdout, &out[0], size & 0xffffffff, &dwRead, nullptr);
    if ( bSuccess == FALSE )
    {
        return Err(ErrorCode::ExternalApiCallFailed);
    }
    out.resize(dwRead);

    return Ok(out);
}


Result<usize>
pwn::windows::ctf::Process::peek_internal()
{
    return Err(ErrorCode::NotImplementedError);
}


Result<bool>
pwn::windows::ctf::Process::CreateInOutPipes()
{
    bool bSuccess           = false;
    SECURITY_ATTRIBUTES sa  = {0};
    sa.nLength              = sizeof(SECURITY_ATTRIBUTES);
    sa.bInheritHandle       = true;
    sa.lpSecurityDescriptor = nullptr;

    //
    // Create the redirection pipes
    //
    bSuccess = (::CreatePipe(&m_ChildPipeStdin, &m_ParentPipeStdin, &sa, 1) == TRUE) &&
               (::CreatePipe(&m_ParentPipeStdout, &m_ChildPipeStdout, &sa, 1) == TRUE);

    //
    // Mark the child handles as inheritable
    //
    bSuccess &= (::SetHandleInformation(m_ChildPipeStdout, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT) == TRUE) &&
                (::SetHandleInformation(m_ChildPipeStdin, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT) == TRUE);

    //
    // Unmark the parent handles as inheritable
    //
    bSuccess &= (::SetHandleInformation(m_ParentPipeStdout, ~HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT) == TRUE) &&
                (::SetHandleInformation(m_ParentPipeStdin, ~HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT) == TRUE);

    if ( !bSuccess )
    {
        return Err(ErrorCode::InitializationFailed);
    }

    return Ok(bSuccess);
}


Result<bool>
pwn::windows::ctf::Process::Spawn(bool StartSuspended)
{
    STARTUPINFO si         = {0};
    PROCESS_INFORMATION pi = {nullptr};
    DWORD CreationFlags    = 0;

    if ( Failed(CreateInOutPipes()) )
    {
        return Err(ErrorCode::InitializationFailed);
    }

    si.cb         = sizeof(STARTUPINFO);
    si.hStdInput  = m_ChildPipeStdin;
    si.hStdError  = m_ChildPipeStdout;
    si.hStdOutput = m_ChildPipeStdout;
    si.dwFlags    = STARTF_USESTDHANDLES;

    CreationFlags |= CREATE_NEW_CONSOLE;
    CreationFlags |= StartSuspended ? CREATE_SUSPENDED : 0;

    if ( FALSE == ::CreateProcessW(
                      nullptr,
                      (LPWSTR)m_CommandLine.c_str(),
                      nullptr,
                      nullptr,
                      true,
                      CreationFlags,
                      nullptr,
                      nullptr,
                      reinterpret_cast<LPSTARTUPINFOW>(&si),
                      reinterpret_cast<LPPROCESS_INFORMATION>(&pi)) )
    {
        return Err(ErrorCode::InitializationFailed);
    }

    ::CloseHandle(m_ChildPipeStdin);
    ::CloseHandle(m_ChildPipeStdout);
    m_ChildPipeStdin  = INVALID_HANDLE_VALUE;
    m_ChildPipeStdout = INVALID_HANDLE_VALUE;

    m_Process = pwn::windows::Process(pi.dwProcessId, pi.hProcess, false);
    return Ok(m_Process.IsValid());
}


pwn::windows::Process&
pwn::windows::ctf::Process::Object()
{
    return m_Process;
}
