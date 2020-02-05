#include "job.h"


HANDLE pwn::job::create()
{
	return ::CreateJobObject(nullptr, nullptr);
}


HANDLE pwn::job::create(_In_ const std::wstring& name)
{
	HANDLE hJob = ::CreateJobObject(nullptr, name.data());
	if ( hJob )
		return hJob;

	if ( ::GetLastError() == ERROR_ALREADY_EXISTS )
		hJob = ::OpenJobObject(JOB_OBJECT_ALL_ACCESS, FALSE, name.data());

	return hJob;
}


BOOL pwn::job::close(_In_ HANDLE hJob)
{
	return ::CloseHandle(hJob);
}


BOOL pwn::job::add_process(_In_ HANDLE hJob, _In_ DWORD dwProcessId)
{
	HANDLE hProcess = ::OpenProcess(PROCESS_SET_QUOTA | PROCESS_TERMINATE, FALSE, dwProcessId); 
	if ( !hProcess )
		return FALSE; 
	
	BOOL success = ::AssignProcessToJobObject(hJob, hProcess); 
	::CloseHandle(hProcess); 
	return success;
}
