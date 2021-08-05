#pragma once

#include "common.h"

#include <variant>
#include "context.h"

using flattenable_t = std::variant<
	std::string, 
	std::wstring, 
	std::vector<BYTE>
>;

namespace pwn::utils
{
	namespace random
	{
		PWNAPI void seed();
		PWNAPI auto rand() -> QWORD;
		PWNAPI auto rand(_In_ ULONG min, _In_ ULONG max) -> QWORD;
		PWNAPI auto byte() -> BYTE;
		PWNAPI auto word() -> WORD;
		PWNAPI auto dword() -> DWORD;
		PWNAPI auto qword() -> QWORD;
		PWNAPI auto string(_In_ ULONG length) -> std::wstring;
		PWNAPI auto alnum(_In_ ULONG length) -> std::wstring;
		PWNAPI auto buffer(_In_ ULONG length) -> std::vector<BYTE>;
	}


	PWNAPI auto base64_encode(_In_ const u8 *bytes_to_encode, _In_ size_t in_len) -> std::string;
    PWNAPI auto base64_encode(_In_ std::vector<BYTE> const &bytes) -> std::string;
	PWNAPI auto base64_decode(_In_ std::string const& encoded_string) -> std::vector<BYTE>;

	PWNAPI auto string_to_widestring(_In_ const std::string& s) -> std::wstring;
	PWNAPI auto widestring_to_string(_In_ const std::wstring& ws) -> std::string;
	PWNAPI auto wstring_to_bytes(_In_ const std::wstring& str) -> std::vector<BYTE>;
	PWNAPI auto string_to_bytes(_In_ std::string const& str) -> std::vector<BYTE>;
	PWNAPI auto to_widestring(_In_ const char* str) -> std::wstring;
	PWNAPI auto split(_In_ const std::wstring& ws, _In_ wchar_t delim) -> std::vector<std::wstring>;
	PWNAPI auto join(_In_ const std::vector<std::wstring>& args) -> std::wstring;

	namespace path
	{
		PWNAPI auto abspath(_In_ const std::wstring& path) -> std::wstring;
	}
	
	PWNAPI auto startswith(_In_ const std::string& str, _In_ const std::string& pattern) -> BOOL;
	PWNAPI auto startswith(_In_ const std::wstring& str, _In_ const std::wstring& pattern) -> BOOL;
	PWNAPI auto endswith(_In_ const std::string& str, _In_ const std::string& pattern) -> BOOL;
	PWNAPI auto endswith(_In_ const std::wstring& str, _In_ const std::wstring& pattern) -> BOOL;

	PWNAPI auto p8 (_In_  BYTE v) -> std::vector<BYTE>;
	PWNAPI auto p16(_In_  WORD v) -> std::vector<BYTE>;
	PWNAPI auto p32(_In_ DWORD v) -> std::vector<BYTE>;
	PWNAPI auto p64(_In_ QWORD v) -> std::vector<BYTE>;

	PWNAPI auto flatten(_In_ const std::vector<flattenable_t>& args) -> std::vector<BYTE>;
	
	PWNAPI auto cyclic(_In_ DWORD dwSize, _In_ DWORD dwPeriod, _Out_ std::vector<BYTE>& buffer) -> BOOL;
	PWNAPI auto cyclic(_In_ DWORD dwSize, _In_ DWORD dwPeriod) -> std::vector<BYTE>;
	PWNAPI auto cyclic(_In_ DWORD dwSize, _Out_ std::vector<BYTE>& buffer) -> BOOL;
	PWNAPI auto cyclic(_In_ DWORD dwSize) -> std::vector<BYTE>;

	PWNAPI void hexdump(_In_ PBYTE Buffer, _In_ SIZE_T BufferSize);
	PWNAPI void hexdump(_In_ const std::vector<BYTE>& bytes);

	PWNAPI void pause();
}