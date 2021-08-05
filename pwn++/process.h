#pragma once

#include "common.h"
#include "nt.h"

#include <AccCtrl.h>
#include <optional>

namespace pwn::process
{
	PWNAPI auto pid() -> DWORD;
	PWNAPI auto ppid() -> DWORD;
	PWNAPI auto list() -> std::vector< std::tuple<std::wstring, DWORD> >;
	_Success_(return == ERROR_SUCCESS) PWNAPI auto get_integrity_level(_In_ DWORD dwProcessId, _Out_ std::wstring & IntegrityLevelName) -> DWORD;
	_Success_(return == ERROR_SUCCESS) PWNAPI auto get_integrity_level(_Out_ std::wstring & IntegrityLevelName) -> DWORD; 
	PWNAPI auto get_integrity_level() -> std::optional<std::wstring>;
	
	PWNAPI _Success_(return) auto execv(_In_ const wchar_t* lpCommandLine, _In_ DWORD dwParentPid, _Out_ LPHANDLE lpNewProcessHandle) -> BOOL;
	PWNAPI auto execv(_In_ const wchar_t* lpCommandLine, _In_opt_ DWORD dwParentPid = 0) -> std::optional<HANDLE>;
	_Success_(return) PWNAPI auto system(_In_ const std::wstring & lpCommandLine, _In_ const std::wstring & operation = L"open") -> BOOL;

	_Success_(return) PWNAPI auto kill(_In_ DWORD dwProcessPid) -> BOOL;
	_Success_(return) PWNAPI auto kill(_In_ HANDLE hProcess) -> BOOL;
	_Success_(return != nullptr) PWNAPI auto cmd() -> HANDLE;
	_Success_(return) PWNAPI auto is_elevated(_In_opt_ DWORD dwPid = 0) -> BOOL;
	_Success_(return) PWNAPI auto add_privilege(_In_ const wchar_t* lpszPrivilegeName, _In_opt_ DWORD dwPid = 0) -> BOOL;
	_Success_(return) PWNAPI auto has_privilege(_In_ const wchar_t* lpwszPrivilegeName, _In_opt_ DWORD dwPid = 0) -> BOOL;

	PWNAPI auto peb() -> PPEB;
	PWNAPI auto teb() -> PTEB;

	namespace mem
	{
		PWNAPI auto write(_In_ HANDLE hProcess, _In_ ULONG_PTR Address, _In_ PBYTE Data, _In_ SIZE_T DataLength) -> SIZE_T;
		PWNAPI auto write(_In_ HANDLE hProcess, _In_ ULONG_PTR Address, _In_ std::vector<BYTE>& Data) -> SIZE_T;
		PWNAPI auto write(_In_ ULONG_PTR Address, _In_ PBYTE Data, _In_ SIZE_T DataLength) -> SIZE_T;
		PWNAPI auto write(_In_ ULONG_PTR Address, _In_ std::vector<BYTE>& Data) -> SIZE_T;

		PWNAPI auto read(_In_ HANDLE hProcess, _In_ ULONG_PTR Address, _In_ SIZE_T DataLength) -> std::vector<BYTE>;
		PWNAPI auto read(_In_ ULONG_PTR Address, _In_ SIZE_T DataLength) -> std::vector<BYTE>;

		PWNAPI auto alloc(_In_ HANDLE hProcess, _In_ SIZE_T Size, _In_ const wchar_t* Permission, _In_opt_ ULONG_PTR Address = NULL) -> ULONG_PTR;
		PWNAPI auto alloc(_In_ SIZE_T Size, _In_ const wchar_t Permission[3], _In_opt_ ULONG_PTR Address = NULL) -> ULONG_PTR;

		PWNAPI auto free(_In_ HANDLE hProcess, _In_ ULONG_PTR Address) -> ULONG_PTR;
		PWNAPI auto free(_In_ ULONG_PTR Address) -> ULONG_PTR;
	}


	namespace appcontainer
	{
		class AppContainer
		{
		public:
			PWNAPI AppContainer(_In_ std::wstring  container_name, _In_ std::wstring  executable_path, _In_ std::vector<WELL_KNOWN_SID_TYPE>  DesiredCapabilities = {});
			PWNAPI ~AppContainer();

			_Success_(return) PWNAPI auto allow_file_or_directory(_In_ const wchar_t* file_or_directory_name) -> BOOL;
			_Success_(return) PWNAPI auto allow_file_or_directory(_In_ const std::wstring& file_or_directory_name) -> BOOL;

			_Success_(return) PWNAPI auto allow_registry_key(_In_ const wchar_t* regkey) -> BOOL;
			_Success_(return) PWNAPI auto allow_registry_key(_In_ const std::wstring& regkey) -> BOOL;

			_Success_(return) PWNAPI auto spawn() -> BOOL;
			_Success_(return) PWNAPI auto restore_acls() -> BOOL;
			_Success_(return) PWNAPI auto join(_In_ DWORD dwTimeout = INFINITE) -> BOOL;



		private:
			auto set_named_object_access(_In_ PWSTR ObjectName, _In_ SE_OBJECT_TYPE ObjectType, _In_ ACCESS_MODE AccessMode, _In_ ACCESS_MASK AccessMask) -> BOOL;

			std::wstring m_ContainerName;
			std::wstring m_ExecutablePath;
			std::vector<WELL_KNOWN_SID_TYPE> m_Capabilities;
			std::vector< std::tuple<std::wstring, SE_OBJECT_TYPE, PACL> > m_OriginalAcls;
			std::wstring m_SidAsString;
			std::wstring m_FolderPath;

			PSID m_AppContainerSid = nullptr;
			STARTUPINFOEX m_StartupInfo = {{0}};
			PROCESS_INFORMATION m_ProcessInfo = {nullptr};
			SECURITY_CAPABILITIES m_SecurityCapabilities = { nullptr };
		};
	}
}
