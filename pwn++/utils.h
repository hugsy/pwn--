#pragma once

#include "common.h"


namespace pwn::utils
{
    PWNAPI QWORD rand(void);
    PWNAPI void hexdump(_In_ const PBYTE Buffer, _In_ SIZE_T BufferSize);
    PWNAPI void hexdump(_In_ const std::vector<BYTE>& bytes);
    PWNAPI std::vector<BYTE> base64_decode(_In_ std::string const& encoded_string);
    PWNAPI std::string base64_encode(unsigned char const* bytes_to_encode, unsigned int in_len);
    PWNAPI std::string widestring_to_string(_In_ const std::wstring& ws);
    PWNAPI std::wstring to_widestring(_In_ const char* str);
}