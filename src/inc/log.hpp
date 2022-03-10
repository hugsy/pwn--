#pragma once

#include <format>
#include <iostream>
#include <mutex>
#include <source_location>
#include <string>

#include "common.hpp"

#ifdef PWN_LOG_USE_COLOR
#define COLOR_RESET L"\033[0m"
#define COLOR_BOLD L"\033[1m"
#define COLOR_UNDERLINE L"\033[4m"
#define COLOR_FG_BLACK L"\033[30m"
#define COLOR_FG_RED L"\033[31m"
#define COLOR_FG_GREEN L"\033[32m"
#define COLOR_FG_YELLOW L"\033[33m"
#define COLOR_FG_BLUE L"\033[34m"
#define COLOR_FG_MAGENTA L"\033[35m"
#define COLOR_FG_CYAN L"\033[36m"
#define COLOR_FG_WHITE L"\033[37m"
#else
#define COLOR_RESET
#define COLOR_BOLD
#define COLOR_UNDERLINE
#define COLOR_FG_BLACK
#define COLOR_FG_RED
#define COLOR_FG_GREEN
#define COLOR_FG_YELLOW
#define COLOR_FG_BLUE
#define COLOR_FG_MAGENTA
#define COLOR_FG_CYAN
#define COLOR_FG_WHITE
#endif


namespace pwn::log
{
enum class log_level_t : u8
{
    LOG_DEBUG,
    LOG_INFO,
    LOG_OK,
    LOG_SUCCESS,
    LOG_WARNING,
    LOG_ERROR,
    LOG_CRITICAL,
};


///
/// @brief Generic logging function.
/// Note: prefer using the macros `dbg`, `info`, `ok`, `warn` and `err`
///
/// @param [inout] level
/// @param [inout] location
/// @param [inout] args
///
template<typename... Args>
void
xlog(
    _In_ log_level_t level,
    _In_ const std::source_location& location,
    _In_ std::wstring const& fmt,
    _In_ Args&&... args)
{
    const wchar_t* prio;
    switch ( level )
    {
    case log_level_t::LOG_DEBUG:
        prio = COLOR_BOLD L"[DEBUG] " COLOR_RESET;
        break;

    case log_level_t::LOG_INFO:
        prio = COLOR_BOLD COLOR_FG_CYAN L"[INFO] " COLOR_RESET;
        break;

    case log_level_t::LOG_WARNING:
        prio = COLOR_BOLD COLOR_FG_YELLOW L"[WARN] " COLOR_RESET;
        break;

    case log_level_t::LOG_ERROR:
        prio = COLOR_BOLD COLOR_FG_RED L"[ERROR] " COLOR_RESET;
        break;

    case log_level_t::LOG_CRITICAL:
        prio = COLOR_BOLD COLOR_FG_MAGENTA L"[CRITICAL] " COLOR_RESET;
        break;

    default:
        return;
    }

    std::wostringstream stream;
    stream << prio << L" (" << location.file_name() << L":" << location.line() << L":" << location.function_name()
           << "()] ";


    stream << std::vformat(std::wstring_view(fmt), std::make_wformat_args(args...)) << std::endl;
    std::wcerr << stream.str() << std::flush;
}


#ifdef __PWNLIB_WINDOWS_BUILD__
///
/// @brief Basic equivalent of Linux Glibc's `perror`
///
/// @param [inout] prefix
///
void PWNAPI
perror(_In_ const std::wstring& prefix);


///
/// @brief `perror` but for NTSTATUS.
///
/// @param [inout] prefix
/// @param [inout] Status
///
void PWNAPI
ntperror(_In_ const wchar_t* prefix, _In_ NTSTATUS Status);
#endif

} // namespace pwn::log

///
/// Convenience logging macros
///
#define dbg(...) pwn::log::xlog(pwn::log::log_level_t::LOG_DEBUG, std::source_location::current(), ##__VA_ARGS__)
#define info(...) pwn::log::xlog(pwn::log::log_level_t::LOG_INFO, std::source_location::current(), ##__VA_ARGS__)
#define ok(...) pwn::log::xlog(pwn::log::log_level_t::LOG_SUCCESS, std::source_location::current(), ##__VA_ARGS__)
#define warn(...) pwn::log::xlog(pwn::log::log_level_t::LOG_WARNING, std::source_location::current(), ##__VA_ARGS__)
#define err(...) pwn::log::xlog(pwn::log::log_level_t::LOG_ERROR, std::source_location::current(), ##__VA_ARGS__)


///
/// toString()-like traits
///
std::wostream&
operator<<(std::wostream& wos, Architecture a);


std::wostream&
operator<<(std::wostream& wos, Endianess e);
