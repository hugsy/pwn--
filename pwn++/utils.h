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
		PWNAPI void seed(void);
		PWNAPI QWORD rand(void);
		PWNAPI QWORD rand(_In_ ULONG min, _In_ ULONG max);
		PWNAPI BYTE byte(void);
		PWNAPI WORD word(void);
		PWNAPI DWORD dword(void);
		PWNAPI QWORD qword(void);
		PWNAPI std::wstring string(_In_ ULONG length);
		PWNAPI std::wstring alnum(_In_ ULONG length);
		PWNAPI std::vector<BYTE> buffer(_In_ ULONG length);
	}


	PWNAPI std::string base64_encode(unsigned char const* bytes_to_encode, unsigned int in_len);
	PWNAPI std::vector<BYTE> base64_decode(_In_ std::string const& encoded_string);

	PWNAPI std::wstring string_to_widestring(_In_ const std::string& s);
	PWNAPI std::string widestring_to_string(_In_ const std::wstring& ws);
	PWNAPI std::vector<BYTE> wstring_to_bytes(_In_ const std::wstring& str);
	PWNAPI std::vector<BYTE> string_to_bytes(_In_ std::string const& str);
	PWNAPI std::wstring to_widestring(_In_ const char* str);
	PWNAPI std::vector<std::wstring> split(_In_ const std::wstring& ws, _In_ const wchar_t delim);
	PWNAPI std::wstring join(_In_ const std::vector<std::wstring>& args);

	namespace path
	{
		PWNAPI std::wstring abspath(_In_ const std::wstring& path);
	}
	
	PWNAPI BOOL startswith(_In_ const std::string& str, _In_ const std::string& pattern);
	PWNAPI BOOL startswith(_In_ const std::wstring& str, _In_ const std::wstring& pattern);
	PWNAPI BOOL endswith(_In_ const std::string& str, _In_ const std::string& pattern);
	PWNAPI BOOL endswith(_In_ const std::wstring& str, _In_ const std::wstring& pattern);

	PWNAPI std::vector<BYTE> p8 (_In_  BYTE v);
	PWNAPI std::vector<BYTE> p16(_In_  WORD v);
	PWNAPI std::vector<BYTE> p32(_In_ DWORD v);
	PWNAPI std::vector<BYTE> p64(_In_ QWORD v);

	PWNAPI std::vector<BYTE> flatten(_In_ const std::vector<flattenable_t>& args);
	
	PWNAPI BOOL cyclic(_In_ DWORD dwSize, _In_ DWORD dwPeriod, _Out_ std::vector<BYTE>& buffer);
	PWNAPI std::vector<BYTE> cyclic(_In_ DWORD dwSize, _In_ DWORD dwPeriod);
	PWNAPI BOOL cyclic(_In_ DWORD dwSize, _Out_ std::vector<BYTE>& buffer);
	PWNAPI std::vector<BYTE> cyclic(_In_ DWORD dwSize);

	PWNAPI void hexdump(_In_ const PBYTE Buffer, _In_ SIZE_T BufferSize);
	PWNAPI void hexdump(_In_ const std::vector<BYTE>& bytes);

}