// clang-format off
#include "CTF/Win32/Process.hpp"

#include <functional>
#include <iostream>
#include <iterator>
#include <queue>
#include <stdexcept>
#include <string>
#include <thread>
#include <utility>

#include "Context.hpp"
#include "Handle.hpp"
#include "Log.hpp"
#include "Tube.hpp"
#include "Utils.hpp"

#include "Win32/Process.hpp"
// clang-format on


///
/// @file Process
///


CTF::Process::Process(std::wstring_view const& CommandLine) : m_CommandLine(CommandLine)
{
}


CTF::Process::~Process()
{
}


Result<usize>
CTF::Process::send_internal(_In_ std::vector<u8> const& out)
{
    DWORD bytesWritten = 0;

    auto bSuccess = ::WriteFile(m_ParentPipeStdin, &out[0], out.size() & 0xffffffff, &bytesWritten, nullptr);
    if ( bSuccess == FALSE )
    {
        return Err(Error::ExternalApiCallFailed);
    }

    return Ok((usize)bytesWritten);
}


Result<std::vector<u8>>
CTF::Process::recv_internal(_In_ usize size)
{
    DWORD dwRead = 0;
    std::vector<u8> out;

    size = MIN(size, Tube::PIPE_DEFAULT_SIZE) & 0xffffffff;
    out.clear();
    out.resize(size);

    auto bSuccess = ::ReadFile(m_ParentPipeStdout, &out[0], size & 0xffffffff, &dwRead, nullptr);
    if ( bSuccess == FALSE )
    {
        return Err(Error::ExternalApiCallFailed);
    }
    out.resize(dwRead);

    return Ok(out);
}


Result<usize>
CTF::Process::peek_internal()
{
    return Err(Error::NotImplementedError);
}


Result<bool>
CTF::Process::CreateInOutPipes()
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

    if ( !bSuccess )
    {
        err("CreatePipe() failed()");
        return Err(Error::InitializationFailed);
    }

    //
    // Mark the child handles as inheritable
    //
    bSuccess &= (::SetHandleInformation(m_ChildPipeStdout, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT) == TRUE) &&
                (::SetHandleInformation(m_ChildPipeStdin, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT) == TRUE);

    if ( !bSuccess )
    {
        err("SetHandleInformation(Child) failed");
        return Err(Error::InitializationFailed);
    }

    //
    // Unmark the parent handles as inheritable
    //
    bSuccess &= (::SetHandleInformation(m_ParentPipeStdout, ~HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT) == TRUE) &&
                (::SetHandleInformation(m_ParentPipeStdin, ~HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT) == TRUE);

    if ( !bSuccess )
    {
        err("SetHandleInformation(Parent) failed");
        return Err(Error::InitializationFailed);
    }

    return Ok(bSuccess);
}


Result<bool>
CTF::Process::Spawn(bool StartSuspended)
{
    STARTUPINFO si         = {0};
    PROCESS_INFORMATION pi = {nullptr};
    DWORD CreationFlags    = 0;

    if ( Failed(CreateInOutPipes()) )
    {
        return Err(Error::InitializationFailed);
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
        return Err(Error::InitializationFailed);
    }

    ::CloseHandle(m_ChildPipeStdin);
    ::CloseHandle(m_ChildPipeStdout);
    m_ChildPipeStdin  = INVALID_HANDLE_VALUE;
    m_ChildPipeStdout = INVALID_HANDLE_VALUE;

    try
    {
        m_Process = std::move(pwn::Process::Process(pi.dwProcessId));
        return Ok(true);
    }
    catch ( const std::exception& e )
    {
        err("Caught exception: ", e.what());
        return Err(Error::InitializationFailed);
    }

    // unreachable
    std::abort();
}


pwn::Process::Process&
CTF::Process::Object()
{
    return m_Process;
}
