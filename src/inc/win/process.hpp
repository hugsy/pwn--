#pragma once

#include "common.hpp"
#include "win/nt.hpp"

#include <AccCtrl.h>
#include <optional>

namespace pwn::win::process
{
	PWNAPI auto pid() -> u32;
	PWNAPI auto ppid() -> std::optional<u32>;
	PWNAPI auto list() -> std::vector< std::tuple<std::wstring, u32> >;
	_Success_(return == ERROR_SUCCESS) PWNAPI auto get_integrity_level(_In_ u32 dwProcessId, _Out_ std::wstring & IntegrityLevelName) -> u32;
	_Success_(return == ERROR_SUCCESS) PWNAPI auto get_integrity_level(_Out_ std::wstring & IntegrityLevelName) -> u32;
	PWNAPI auto get_integrity_level() -> std::optional<std::wstring>;

	PWNAPI _Success_(return) auto execv(_In_ const wchar_t* lpCommandLine, _In_ u32 dwParentPid, _Out_ LPHANDLE lpNewProcessHandle) -> bool;
	PWNAPI auto execv(_In_ const wchar_t* lpCommandLine, _In_opt_ u32 dwParentPid = 0) -> std::optional<HANDLE>;
	_Success_(return) PWNAPI auto system(_In_ const std::wstring & lpCommandLine, _In_ const std::wstring & operation = L"open") -> bool;

	_Success_(return) PWNAPI auto kill(_In_ u32 dwProcessPid) -> bool;
	_Success_(return) PWNAPI auto kill(_In_ HANDLE hProcess) -> bool;
	_Success_(return != nullptr) PWNAPI auto cmd() -> HANDLE;
	_Success_(return) PWNAPI auto is_elevated(_In_opt_ u32 dwPid = 0) -> bool;
	_Success_(return) PWNAPI auto add_privilege(_In_ const wchar_t* lpszPrivilegeName, _In_opt_ u32 dwPid = 0) -> bool;
	_Success_(return) PWNAPI auto has_privilege(_In_ const wchar_t* lpwszPrivilegeName, _In_opt_ u32 dwPid = 0) -> bool;

	PWNAPI auto peb() -> PPEB;
	PWNAPI auto teb() -> PTEB;

	namespace mem
	{
		PWNAPI auto write(_In_ HANDLE hProcess, _In_ uptr Address, _In_ u8* Data, _In_ size_t DataLength) -> size_t;
		PWNAPI auto write(_In_ HANDLE hProcess, _In_ uptr Address, _In_ std::vector<u8>& Data) -> size_t;
		PWNAPI auto write(_In_ uptr Address, _In_ u8* Data, _In_ size_t DataLength) -> size_t;
		PWNAPI auto write(_In_ uptr Address, _In_ std::vector<u8>& Data) -> size_t;

		PWNAPI auto read(_In_ HANDLE hProcess, _In_ uptr Address, _In_ size_t DataLength) -> std::vector<u8>;
		PWNAPI auto read(_In_ uptr Address, _In_ size_t DataLength) -> std::vector<u8>;

		PWNAPI auto alloc(_In_ HANDLE hProcess, _In_ size_t Size, _In_ const wchar_t* Permission, _In_opt_ uptr Address = NULL) -> uptr;
		PWNAPI auto alloc(_In_ size_t Size, _In_ const wchar_t Permission[3], _In_opt_ uptr Address = NULL) -> uptr;

		PWNAPI auto free(_In_ HANDLE hProcess, _In_ uptr Address) -> uptr;
		PWNAPI auto free(_In_ uptr Address) -> uptr;
	}


	namespace appcontainer
	{
		class AppContainer
		{
		public:
			PWNAPI AppContainer(_In_ std::wstring  container_name, _In_ std::wstring  executable_path, _In_ std::vector<WELL_KNOWN_SID_TYPE>  DesiredCapabilities = {});
			PWNAPI ~AppContainer();

			_Success_(return) PWNAPI auto allow_file_or_directory(_In_ const wchar_t* file_or_directory_name) -> bool;
			_Success_(return) PWNAPI auto allow_file_or_directory(_In_ const std::wstring& file_or_directory_name) -> bool;

			_Success_(return) PWNAPI auto allow_registry_key(_In_ const wchar_t* regkey) -> bool;
			_Success_(return) PWNAPI auto allow_registry_key(_In_ const std::wstring& regkey) -> bool;

			_Success_(return) PWNAPI auto spawn() -> bool;
			_Success_(return) PWNAPI auto restore_acls() -> bool;
			_Success_(return) PWNAPI auto join(_In_ u32 dwTimeout = INFINITE) -> bool;



		private:
			auto set_named_object_access(_In_ PWSTR ObjectName, _In_ SE_OBJECT_TYPE ObjectType, _In_ ACCESS_MODE AccessMode, _In_ ACCESS_MASK AccessMask) -> bool;

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
