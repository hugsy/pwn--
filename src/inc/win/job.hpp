#pragma once

#include "common.hpp"
#include "handle.hpp"


namespace pwn::win::job
{

// todo:
// limit_cpufreq_for_job
// assign_job_to_core

class Job
{
public:
    pwn::win::job::Job(_In_ LPCWSTR name = nullptr) : m_name(name)
    {
        HANDLE hJob = ::CreateJobObject(nullptr, name);
        if ( !hJob && ::GetLastError() == ERROR_ALREADY_EXISTS )
        {
            hJob = ::OpenJobObject(JOB_OBJECT_ALL_ACCESS, FALSE, name);
        }

        if ( !hJob )
            throw std::exception("cannot create job");

        m_hJob.m_handle = hJob;
    }


    Job& operator+=(u32 ProcessId)&
    {
        if(!add_process(ProcessId))
            throw std::exception("cannot add process");

        return *this;
    }


private:
    auto
    add_process(_In_ u32 ProcessId) -> bool;

    std::wstring m_name;
    pwn::utils::GenericHandle<HANDLE> m_hJob;
    std::vector<pwn::utils::GenericHandle<HANDLE>> m_handles;
};
} // namespace pwn::win::job
