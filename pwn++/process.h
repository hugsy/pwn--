#pragma once

#include "common.h"
#include "nt.h"

namespace pwn::process
{
	typedef struct _process_t
	{
		std::wstring name;
		DWORD pid = -1;
	} process_t;

	PWNAPI DWORD pid();
	PWNAPI DWORD ppid();
	PWNAPI std::vector<process_t> list();
	_Success_(return == ERROR_SUCCESS) PWNAPI DWORD get_integrity_level(_In_ DWORD dwProcessId, _Out_ std::wstring & IntegrityLevelName);
	_Success_(return == ERROR_SUCCESS) PWNAPI DWORD get_integrity_level(_Out_ std::wstring & IntegrityLevelName); 
	_Success_(return) PWNAPI BOOL execv(_In_ const wchar_t* lpCommandLine, _Out_opt_ LPHANDLE lpNewProcessHandle = nullptr);
	_Success_(return) PWNAPI BOOL execv(_In_ const wchar_t* lpCommandLine, _In_opt_ DWORD dwParentPid = 0, _Out_opt_ LPHANDLE lpNewProcessHandle = nullptr);
	_Success_(return) PWNAPI BOOL kill(_In_ DWORD dwProcessPid);
	_Success_(return) PWNAPI BOOL kill(_In_ HANDLE hProcess);
	_Success_(return != nullptr) PWNAPI HANDLE cmd();
	_Success_(return) PWNAPI BOOL is_elevated(_In_opt_ DWORD dwPid = 0);
	_Success_(return) PWNAPI BOOL add_privilege(_In_ const wchar_t* lpszPrivilegeName, _In_opt_ DWORD dwPid = 0);
	_Success_(return) PWNAPI BOOL has_privilege(_In_ const wchar_t* lpwszPrivilegeName, _In_opt_ DWORD dwPid = 0);

	PWNAPI PPEB peb();
	PWNAPI PTEB teb();

	namespace mem
	{
		PWNAPI SIZE_T write(_In_ HANDLE hProcess, _In_ ULONG_PTR Address, _In_ PBYTE Data, _In_ SIZE_T DataLength);
		PWNAPI SIZE_T write(_In_ HANDLE hProcess, _In_ ULONG_PTR Address, _In_ std::vector<BYTE>& Data);
		PWNAPI SIZE_T write(_In_ ULONG_PTR Address, _In_ PBYTE Data, _In_ SIZE_T DataLength);
		PWNAPI SIZE_T write(_In_ ULONG_PTR Address, _In_ std::vector<BYTE>& Data);

		PWNAPI std::vector<BYTE> read(_In_ HANDLE hProcess, _In_ ULONG_PTR Address, _In_ SIZE_T DataLength);
		PWNAPI std::vector<BYTE> read(_In_ ULONG_PTR Address, _In_ SIZE_T DataLength);

		PWNAPI ULONG_PTR alloc(_In_ HANDLE hProcess, _In_ SIZE_T Size, _In_ const wchar_t* Permission, _In_opt_ ULONG_PTR Address = NULL);
		PWNAPI ULONG_PTR alloc(_In_ SIZE_T Size, _In_ const wchar_t Permission[3], _In_opt_ ULONG_PTR Address = NULL);

		PWNAPI ULONG_PTR free(_In_ HANDLE hProcess, _In_ ULONG_PTR Address);
		PWNAPI ULONG_PTR free(_In_ ULONG_PTR Address);
	}
}
