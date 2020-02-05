#pragma once

#include "common.h"


namespace pwn::utils
{
    DWORD PWNAPI rand(void);
    void PWNAPI hexdump(_In_ const PBYTE Buffer, _In_ SIZE_T BufferSize);
    void PWNAPI hexdump(_In_ const std::vector<BYTE>& bytes);
    std::vector<BYTE> PWNAPI base64_decode(_In_ std::string const& encoded_string);
    std::string PWNAPI base64_encode(unsigned char const* bytes_to_encode, unsigned int in_len);
    std::string widestring_to_string(_In_ const std::wstring& ws);
    std::wstring to_widestring(_In_ const char* str);
}