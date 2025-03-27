#include "Win32/Job.hpp"

#include "Log.hpp"

using namespace pwn;

auto
Job::Job::AddProcess(u32 ProcessId) -> Result<bool>
{
    auto hProcess = UniqueHandle {::OpenProcess(PROCESS_SET_QUOTA | PROCESS_TERMINATE, false, ProcessId)};
    if ( !hProcess )
    {
        Log::perror(L"OpenProcess()");
        return Err(Error::ExternalApiCallFailed);
    }

    if ( !::AssignProcessToJobObject(m_hJob.get(), hProcess.get()) )
    {
        Log::perror(L"AssignProcessToJobObject()");
        return Err(Error::ExternalApiCallFailed);
    }

    m_Handles.push_back(std::move(hProcess));
    return Ok(true);
}
