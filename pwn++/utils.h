#pragma once

#include "common.h"

#include <variant>

//typedef std::variant<DWORD, QWORD, std::wstring, std::string> flattenable_t;
using flattenable_t = std::variant<DWORD, QWORD, std::wstring, std::string>;

namespace pwn::utils
{
	PWNAPI QWORD rand(void);
	PWNAPI void hexdump(_In_ const PBYTE Buffer, _In_ SIZE_T BufferSize);
	PWNAPI void hexdump(_In_ const std::vector<BYTE>& bytes);
	PWNAPI std::vector<BYTE> base64_decode(_In_ std::string const& encoded_string);
	PWNAPI std::string base64_encode(unsigned char const* bytes_to_encode, unsigned int in_len);
	PWNAPI std::string widestring_to_string(_In_ const std::wstring& ws);
	PWNAPI std::wstring to_widestring(_In_ const char* str);
	PWNAPI BOOL cyclic(_In_ DWORD dwSize, _In_ DWORD dwPeriod, _Out_ std::vector<BYTE>& buffer);
	PWNAPI BOOL cyclic(_In_ DWORD dwSize, _Out_ std::vector<BYTE>& buffer);
	PWNAPI BOOL cyclic(_In_ DWORD dwSize, _Out_ std::vector<BYTE>& buffer);
	PWNAPI std::vector<BYTE> flatten(_In_ std::vector<flattenable_t>& args);
}