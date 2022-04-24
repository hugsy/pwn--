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

#ifdef __PWNLIB_WINDOWS_BUILD__
///
/// @brief perror() style of function for Windows
///
/// @param [inout] prefix
///
void PWNAPI
perror(_In_ const std::wstring& prefix)
{
    auto sysMsg   = std::vector<wchar_t>(1024);
    auto eNum     = ::GetLastError();
    auto sysMsgSz = (DWORD)sysMsg.size();

    ::FormatMessage(
        FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        nullptr,
        eNum,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        sysMsg.data(),
        sysMsgSz,
        nullptr);

    auto sysMsgStr = std::wstring(sysMsg.begin(), sysMsg.end());
    err(L"{}, errcode={:#x}: {}", prefix, eNum, sysMsgStr);
}


void
ntperror(_In_ const wchar_t* prefix, _In_ NTSTATUS Status)
{
    auto dwDosError = ::RtlNtStatusToDosError(Status);
    auto hResult    = HRESULT_FROM_WIN32(dwDosError);
    ::SetLastError(hResult);
    perror(prefix);
}
#endif


} // namespace pwn::log
