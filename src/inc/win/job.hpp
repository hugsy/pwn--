#pragma once

#include "common.hpp"


namespace pwn::job
{
	PWNAPI auto create() -> HANDLE;
	PWNAPI auto create(_In_ const std::wstring& name) -> HANDLE;
	PWNAPI auto close(_In_ HANDLE hJob) -> BOOL;
	PWNAPI auto add_process(_In_ HANDLE hJob, _In_ DWORD dwProcessId) -> BOOL;
	// limit_cpufreq_for_job
	// assign_job_to_core
}
