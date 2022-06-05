#include "log.hpp"

#include <cassert>
#include <cstdio>
#include <format>
#include <iostream>
#include <string>
#include <string_view>
#include <vector>

#include "context.hpp"

namespace pwn::log
{

#ifdef PWN_BUILD_FOR_WINDOWS
///
/// @brief perror() style of function for Windows
///
/// @param [inout] prefix
///
void PWNAPI
perror(_In_ const std::wstring_view& prefix)
{
    const u32 sysMsgSz = 1024;
    auto sysMsg        = std::wstring();
    sysMsg.reserve(sysMsgSz);
    // auto sysMsg   = std::vector<wchar_t>(1024);
    const auto eNum = ::GetLastError();

    ::FormatMessageW(
        FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS | FORMAT_MESSAGE_MAX_WIDTH_MASK,
        nullptr,
        eNum,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        sysMsg.data(),
        sysMsgSz,
        nullptr);

    const usize max_len  = ::wcslen((wchar_t*)sysMsg.c_str());
    const auto sysMsgStr = std::wstring_view(sysMsg.c_str(), max_len);
    err(L"{}, errcode={:#x}: {}", prefix, eNum, sysMsgStr);
}


void
ntperror(_In_ const std::wstring_view& prefix, _In_ NTSTATUS Status)
{
    auto dwDosError = ::RtlNtStatusToDosError(Status);
    auto hResult    = HRESULT_FROM_WIN32(dwDosError);
    ::SetLastError(hResult);
    perror(prefix);
}
#endif


} // namespace pwn::log
