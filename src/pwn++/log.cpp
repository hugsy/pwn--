#include "log.hpp"

#include <cassert>
#include <cstdio>
#include <format>
#include <iostream>
#include <string>
#include <string_view>
#include <vector>

extern struct GlobalContext Context;

namespace pwn::log
{

const char*
GetPriorityString(const LogLevel level)
{
    switch ( level )
    {
    case LogLevel::Debug:
        return PWN_COLOR_BOLD PWN_LOG_STRINGS_DEBUG PWN_COLOR_RESET;

    case LogLevel::Success:
        return PWN_COLOR_BOLD PWN_COLOR_FG_GREEN PWN_LOG_STRINGS_SUCCESS PWN_COLOR_RESET;

    case LogLevel::Info:
        return PWN_COLOR_BOLD PWN_COLOR_FG_CYAN PWN_LOG_STRINGS_INFO PWN_COLOR_RESET;

    case LogLevel::Warning:
        return PWN_COLOR_BOLD PWN_COLOR_FG_YELLOW PWN_LOG_STRINGS_WARN PWN_COLOR_RESET;

    case LogLevel::Error:
        return PWN_COLOR_BOLD PWN_COLOR_FG_RED PWN_LOG_STRINGS_ERROR PWN_COLOR_RESET;

    case LogLevel::Critical:
        return PWN_COLOR_BOLD PWN_COLOR_FG_MAGENTA PWN_LOG_STRINGS_CRITICAL PWN_COLOR_RESET;

    default:
        return "";
    }
}


void
Log(const LogLevel level, std::source_location const& location, std::ostringstream& msg)
{
    std::ostringstream prefix;
    prefix << GetPriorityString(level);

    if ( level == LogLevel::Debug )
    {
        prefix << "{";
        prefix << location.file_name() << ":" << location.line() << ":";
        prefix << location.function_name() << "()";
        prefix << "} ";
    }

    std::cerr << prefix.str() << msg.str() << std::flush;
}


#ifdef PWN_BUILD_FOR_WINDOWS
const wchar_t*
GetPriorityWideString(const LogLevel level)
{
    switch ( level )
    {
    case LogLevel::Debug:
        return WIDECHAR(PWN_COLOR_BOLD) WIDECHAR(PWN_LOG_STRINGS_DEBUG) WIDECHAR(PWN_COLOR_RESET);

    case LogLevel::Success:
        return WIDECHAR(PWN_COLOR_BOLD) WIDECHAR(PWN_COLOR_FG_GREEN) WIDECHAR(PWN_LOG_STRINGS_SUCCESS)
            WIDECHAR(PWN_COLOR_RESET);

    case LogLevel::Info:
        return WIDECHAR(PWN_COLOR_BOLD) WIDECHAR(PWN_COLOR_FG_CYAN) WIDECHAR(PWN_LOG_STRINGS_INFO)
            WIDECHAR(PWN_COLOR_RESET);

    case LogLevel::Warning:
        return WIDECHAR(PWN_COLOR_BOLD) WIDECHAR(PWN_COLOR_FG_YELLOW) WIDECHAR(PWN_LOG_STRINGS_WARN)
            WIDECHAR(PWN_COLOR_RESET);

    case LogLevel::Error:
        return WIDECHAR(PWN_COLOR_BOLD) WIDECHAR(PWN_COLOR_FG_RED) WIDECHAR(PWN_LOG_STRINGS_ERROR)
            WIDECHAR(PWN_COLOR_RESET);

    case LogLevel::Critical:
        return WIDECHAR(PWN_COLOR_BOLD) WIDECHAR(PWN_COLOR_FG_MAGENTA) WIDECHAR(PWN_LOG_STRINGS_CRITICAL)
            WIDECHAR(PWN_COLOR_RESET);

    default:
        return L"";
    }
}


void
Log(const LogLevel level, std::source_location const& location, std::wostringstream& msg)
{
    if(Context.log_level < level)
    {
        return;
    }
    
    std::wostringstream prefix;
    prefix << GetPriorityWideString(level);

    if ( level == LogLevel::Debug )
    {
        prefix << L"{";
        prefix << location.file_name() << L":" << location.line() << L":";
        prefix << location.function_name() << L"()";
        prefix << L"} ";
    }

    std::wcerr << prefix.str() << msg.str() << std::flush;
}


///
/// @brief perror() style of function for Windows
///
/// @param [in] prefix
///
void PWNAPI
perror(const std::wstring_view& prefix)
{
    const u32 sysMsgSz = 1024;
    auto sysMsg        = std::wstring();
    sysMsg.reserve(sysMsgSz);
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


void PWNAPI
perror(const std::string_view& prefix)
{
    const u32 sysMsgSz = 1024;
    auto sysMsg        = std::string();
    sysMsg.reserve(sysMsgSz);
    const auto eNum = ::GetLastError();

    ::FormatMessageA(
        FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS | FORMAT_MESSAGE_MAX_WIDTH_MASK,
        nullptr,
        eNum,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        sysMsg.data(),
        sysMsgSz,
        nullptr);

    const usize max_len  = ::strlen((char*)sysMsg.c_str());
    const auto sysMsgStr = std::string_view(sysMsg.c_str(), max_len);
    err("{}, errcode={:#x}: {}", prefix, eNum, sysMsgStr);
}


void
ntperror(_In_ const std::string_view& prefix, _In_ NTSTATUS Status)
{
    auto dwDosError = ::RtlNtStatusToDosError(Status);
    auto hResult    = HRESULT_FROM_WIN32(dwDosError);
    ::SetLastError(hResult);
    log::perror(prefix);
}

#endif


} // namespace pwn::log
