#include "win32/job.hpp"

auto
pwn::win::job::Job::add_process(_In_ u32 ProcessId) -> bool
{
    auto hProcess = pwn::utils::GenericHandle(
        ::OpenProcess(PROCESS_SET_QUOTA | PROCESS_TERMINATE, false, ProcessId)
    );

    if ( !hProcess )
    {
        perror("OpenProcess()");
        return false;
    }

    if(::AssignProcessToJobObject(m_hJob.get(), hProcess.get()))
    {
        m_handles.push_back(
            pwn::utils::GenericHandle(hProcess.get())
        );
        return true;
    }

    return false;
}
