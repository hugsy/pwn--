#pragma once

#include "common.h"


namespace pwn::job
{
	PWNAPI HANDLE create();
	PWNAPI HANDLE create(_In_ const std::wstring& name);
	PWNAPI BOOL close(_In_ HANDLE hJob);
	PWNAPI BOOL add_process(_In_ HANDLE hJob, _In_ DWORD dwProcessId);
	// limit_cpufreq_for_job
	// assign_job_to_core
}
