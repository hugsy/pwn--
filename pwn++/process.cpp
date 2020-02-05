#include "process.h"
#include "log.h"

using namespace pwn::log;



_Success_(return == ERROR_SUCCESS)
DWORD pwn::process::get_integrity_level(_In_ DWORD dwProcessId, _Out_ std::wstring & IntegrityLevelName)
{
	HANDLE hProcessHandle = INVALID_HANDLE_VALUE;
	HANDLE hProcessToken = INVALID_HANDLE_VALUE;
	DWORD dwRes = ERROR_SUCCESS;
	PTOKEN_MANDATORY_LABEL pTIL = NULL;
	DWORD dwIntegrityLevel = SECURITY_MANDATORY_MEDIUM_RID;

	do
	{
		hProcessHandle = ::OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwProcessId);
		if (hProcessHandle == NULL)
		{
			dwRes = ::GetLastError();
			break;
		}

		if (!::OpenProcessToken(hProcessHandle, TOKEN_QUERY, &hProcessToken))
		{
			dwRes = ::GetLastError();
			break;
		}

		DWORD dwLengthNeeded;

		if (!::GetTokenInformation(hProcessToken, TokenIntegrityLevel, NULL, 0, &dwLengthNeeded))
		{
			dwRes = ::GetLastError();
			if (dwRes != ERROR_INSUFFICIENT_BUFFER)
			{
				dwRes = ::GetLastError();
				break;
			}
		}

		pTIL = (PTOKEN_MANDATORY_LABEL)::LocalAlloc(LPTR, dwLengthNeeded);
		if (!pTIL)
		{
			dwRes = ::GetLastError();
			break;
		}


		if (!::GetTokenInformation(hProcessToken, TokenIntegrityLevel, pTIL, dwLengthNeeded, &dwLengthNeeded))
		{
			dwRes = ::GetLastError();
			if (dwRes != ERROR_INSUFFICIENT_BUFFER)
			{
				dwRes = ::GetLastError();
				break;
			}
		}

		dwIntegrityLevel = *::GetSidSubAuthority(
			pTIL->Label.Sid,
			(DWORD)(UCHAR)(*::GetSidSubAuthorityCount(pTIL->Label.Sid) - 1)
		);

		::LocalFree(pTIL);


		if (dwIntegrityLevel == SECURITY_MANDATORY_LOW_RID)
			IntegrityLevelName = L"Low";

		else if (SECURITY_MANDATORY_MEDIUM_RID < dwIntegrityLevel && dwIntegrityLevel < SECURITY_MANDATORY_HIGH_RID)
			IntegrityLevelName = L"Medium";

		else if (dwIntegrityLevel >= SECURITY_MANDATORY_HIGH_RID)
			IntegrityLevelName = L"High";

		else if (dwIntegrityLevel >= SECURITY_MANDATORY_SYSTEM_RID)
			IntegrityLevelName = L"System";

		else
			IntegrityLevelName = L"Unknown";

	} while (0);

	if (hProcessToken != INVALID_HANDLE_VALUE)
		::CloseHandle(hProcessToken);

	if (hProcessHandle)
		::CloseHandle(hProcessHandle);

	return dwRes;
}


_Success_(return == ERROR_SUCCESS)
DWORD pwn::process::get_integrity_level(_Out_ std::wstring & IntegrityLevelName)
{
	return get_integrity_level(::GetCurrentProcessId(), IntegrityLevelName);
}


_Success_(return)
BOOL pwn::process::execv(_In_ const wchar_t* lpCommandLine, _In_opt_ DWORD dwParentPid, _Out_opt_ LPHANDLE lpNewProcessHandle)
{
	HANDLE hParentProcess = INVALID_HANDLE_VALUE;
	STARTUPINFOEX si = { 0, };
	PROCESS_INFORMATION pi = { 0, };
	DWORD dwFlags = DETACHED_PROCESS | EXTENDED_STARTUPINFO_PRESENT;
	si.StartupInfo.cb = sizeof(STARTUPINFOEX);
	
	size_t cmd_len = ::wcslen(lpCommandLine);

	auto cmd = std::make_unique<WCHAR[]>(cmd_len+1);
	::RtlCopyMemory(cmd.get(), lpCommandLine, 2 * cmd_len);

	if ( dwParentPid )
	{
		hParentProcess = ::OpenProcess(PROCESS_CREATE_PROCESS, FALSE, dwParentPid);
		if ( hParentProcess )
		{
			SIZE_T AttrListSize;
			::InitializeProcThreadAttributeList(nullptr, 1, 0, &AttrListSize);
			si.lpAttributeList = (LPPROC_THREAD_ATTRIBUTE_LIST)::HeapAlloc(::GetProcessHeap(), 0, AttrListSize);
			::InitializeProcThreadAttributeList(si.lpAttributeList, 1, 0, &AttrListSize);
			::UpdateProcThreadAttribute(si.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &hParentProcess, sizeof(HANDLE), nullptr, nullptr);
			dbg(L"Spawning '%s' with PPID=%d...\n", cmd.get(), dwParentPid);
		}
	}
	else
	{
		dbg(L"Spawning '%s'...\n", cmd.get());
	}

	if (!::CreateProcess(NULL, cmd.get(), NULL, NULL, TRUE, dwFlags, NULL, NULL, (LPSTARTUPINFO)&si, &pi))
	{
		perror(L"CreateProcess()");
		return FALSE;
	}

	::CloseHandle(pi.hThread);
	if ( dwParentPid && hParentProcess != INVALID_HANDLE_VALUE)
	{
		::DeleteProcThreadAttributeList(si.lpAttributeList);
		::HeapFree(::GetProcessHeap(), 0, si.lpAttributeList);
		::CloseHandle(hParentProcess);
	}

	dbg(L"'%s' spawned with PID %d\n", lpCommandLine, pi.dwProcessId);
	if(lpNewProcessHandle)
		*lpNewProcessHandle = pi.hProcess;
	else
		::CloseHandle(pi.hProcess);

	return TRUE;
}


_Success_(return)
BOOL pwn::process::execv(_In_ const wchar_t* lpCommandLine, _Out_opt_ LPHANDLE lpNewProcessHandle)
{
	return pwn::process::execv(lpCommandLine, 0, lpNewProcessHandle);
}


_Success_(return)
BOOL pwn::process::kill(_In_ DWORD dwProcessPid)
{
	HANDLE hProcess = ::OpenProcess(PROCESS_TERMINATE, FALSE, dwProcessPid);
	if ( !hProcess )
		return FALSE;
	return kill(hProcess);
}


_Success_(return)
BOOL pwn::process::kill(_In_ HANDLE hProcess)
{
	dbg(L"attempting to kill %u (pid=%u)\n", hProcess, ::GetProcessId(hProcess));
	BOOL res = ::TerminateProcess(hProcess, EXIT_FAILURE);
	::CloseHandle(hProcess);
	return res;
}