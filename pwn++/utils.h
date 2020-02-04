#pragma once

#include "common.h"


namespace pwn::utils
{
    void PWNAPI hexdump(_In_ const PBYTE Buffer, _In_ SIZE_T BufferSize);
    void PWNAPI hexdump(_In_ const std::vector<BYTE>& bytes);
}