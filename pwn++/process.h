#pragma once

#include "common.h"
#include "nt.h"

#include <AccCtrl.h>

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
	_Success_(return) PWNAPI BOOL system(_In_ const std::wstring & lpCommandLine, _In_ const std::wstring & operation = L"open");

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

	/*++/
	Ref: https://scorpiosoftware.net/2019/01/15/fun-with-appcontainers/
	--*/
	namespace appcontainer
	{
		class AppContainer
		{
		public:
			PWNAPI AppContainer(_In_ const std::wstring& container_name, _In_ const std::wstring& executable_path, _In_ const std::vector<WELL_KNOWN_SID_TYPE>& DesiredCapabilities = {});
			PWNAPI ~AppContainer();

			_Success_(return) PWNAPI BOOL allow_file_or_directory(_In_ const wchar_t* file_or_directory_name);
			_Success_(return) PWNAPI BOOL allow_file_or_directory(_In_ const std::wstring& file_or_directory_name);

			_Success_(return) PWNAPI BOOL allow_registry_key(_In_ const wchar_t* regkey);
			_Success_(return) PWNAPI BOOL allow_registry_key(_In_ const std::wstring& regkey);

			_Success_(return) PWNAPI BOOL spawn();
			_Success_(return) PWNAPI BOOL restore_acls();
			_Success_(return) PWNAPI BOOL join(_In_ DWORD dwTimeout = INFINITE);



		private:
			BOOL set_named_object_access(_In_ PWSTR ObjectName, _In_ SE_OBJECT_TYPE ObjectType, _In_ ACCESS_MODE AccessMode, _In_ ACCESS_MASK AccessMask);

			std::wstring m_ContainerName;
			std::wstring m_ExecutablePath;
			std::vector<WELL_KNOWN_SID_TYPE> m_Capabilities;
			std::vector< std::tuple<std::wstring, SE_OBJECT_TYPE, PACL> > m_OriginalAcls;
			std::wstring m_SidAsString;
			std::wstring m_FolderPath;

			PSID m_AppContainerSid = nullptr;
			STARTUPINFOEX m_StartupInfo = {0};
			PROCESS_INFORMATION m_ProcessInfo = {0};
			SECURITY_CAPABILITIES m_SecurityCapabilities = { 0 };
		};
	}
}
