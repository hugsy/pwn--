#pragma once

#include "common.h"


namespace pwn::process
{
	typedef struct _process_t
	{
		std::wstring name;
		DWORD pid;
	} process_t;

	PWNAPI std::vector<process_t> list();
	_Success_(return == ERROR_SUCCESS) PWNAPI DWORD get_integrity_level(_In_ DWORD dwProcessId, _Out_ std::wstring & IntegrityLevelName);
	_Success_(return == ERROR_SUCCESS) PWNAPI DWORD get_integrity_level(_Out_ std::wstring & IntegrityLevelName); 
	_Success_(return) PWNAPI BOOL execv(_In_ const wchar_t* lpCommandLine, _Out_opt_ LPHANDLE lpNewProcessHandle = nullptr);
	_Success_(return) PWNAPI BOOL execv(_In_ const wchar_t* lpCommandLine, _In_opt_ DWORD dwParentPid = 0, _Out_opt_ LPHANDLE lpNewProcessHandle = nullptr);
	_Success_(return) PWNAPI BOOL kill(_In_ DWORD dwProcessPid);
	_Success_(return) PWNAPI BOOL kill(_In_ HANDLE hProcess);

	PWNAPI ULONG_PTR peb();
	PWNAPI ULONG_PTR teb();

	namespace mem
	{
		PWNAPI SIZE_T write(_In_ HANDLE hProcess, _In_ ULONG_PTR Address, _In_ PBYTE Data, _In_ SIZE_T DataLength);
		PWNAPI SIZE_T write(_In_ HANDLE hProcess, _In_ ULONG_PTR Address, _In_ std::vector<BYTE>& Data);
		PWNAPI SIZE_T write(_In_ ULONG_PTR Address, _In_ PBYTE Data, _In_ SIZE_T DataLength);
		PWNAPI SIZE_T write(_In_ ULONG_PTR Address, _In_ std::vector<BYTE>& Data);

		PWNAPI std::vector<BYTE> read(_In_ HANDLE hProcess, _In_ ULONG_PTR Address, _In_ SIZE_T DataLength);
		PWNAPI std::vector<BYTE> read(_In_ ULONG_PTR Address, _In_ SIZE_T DataLength);
	}
}
