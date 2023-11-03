#pragma once

#include "Common.hpp"
#include "Error.hpp"
#include "Handle.hpp"


namespace pwn::Job
{

// todo:
// limit_cpufreq_for_job
// assign_job_to_core

class Job
{
public:
    Job(_In_ LPCWSTR name = nullptr) : m_Name(name), m_Valid {false}
    {
        HANDLE hJob = ::CreateJobObjectW(nullptr, name);
        if ( !hJob && ::GetLastError() == ERROR_ALREADY_EXISTS )
        {
            hJob = ::OpenJobObjectW(JOB_OBJECT_ALL_ACCESS, FALSE, name);
        }

        if ( !hJob )
            throw std::exception("cannot create job");

        m_hJob = UniqueHandle {hJob};

        m_Valid = true;
    }

    bool
    IsValid() const
    {
        return m_Valid;
    }

    auto
    AddProcess(u32 ProcessId) -> Result<bool>;

    ///
    ///@brief Simple C++ friendly wrapper for `AddProcess`
    ///
    ///@param ProcessId
    ///@return Job&
    ///@throws `runtime_error` if adding process to the job failed
    ///
    Job&
    operator+=(u32 ProcessId)
    {
        if ( Success(AddProcess(ProcessId)) )
        {
            return *this;
        }

        throw std::runtime_error("Error adding process to job");
    }


private:
    bool m_Valid {false};
    std::wstring m_Name {};
    UniqueHandle m_hJob {};
    std::vector<UniqueHandle> m_Handles {};
};
} // namespace pwn::Job
