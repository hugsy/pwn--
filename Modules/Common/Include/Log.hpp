///
/// @file log.hpp
/// @brief Logging header: Wide string support on linux is at best flaky, so only Windows version
/// gets both string and wide string support. Linux gets only regular string support.
///
/// @copyright Copyright (c) 2022
///
///
#pragma once

//
// Abstraction for {std,fmt}::format
//
#ifdef PWN_BUILD_FOR_WINDOWS
#include <format>
#define PwnFormatter std::formatter
#define PwnVFormat std::vformat
#define PwnFormat std::format
#define PwnMakeFormatArgs std::make_format_args
#define PwnFormatContext std::format_context
#elif defined(PWN_BUILD_FOR_LINUX)
#include <fmt/core.h>
#include <fmt/format.h>
#define PwnFormatter fmt::formatter
#define PwnFormat fmt::format
#define PwnVFormat fmt::vformat
#define PwnMakeFormatArgs fmt::make_format_args
#define PwnFormatContext fmt::format_context
#endif // PWN_BUILD_FOR_WINDOWS


#include <source_location>
#include <sstream>
#include <string_view>

#include "Common.hpp"

// clang-format off
#ifdef PWN_LOG_USE_COLOR
#define PWN_COLOR_RESET               "\033[0m "
#define PWN_COLOR_BOLD                "\033[1m "
#define PWN_COLOR_UNDERLINE           "\033[4m "
#define PWN_COLOR_FG_BLACK            "\033[30m "
#define PWN_COLOR_FG_RED              "\033[31m "
#define PWN_COLOR_FG_GREEN            "\033[32m "
#define PWN_COLOR_FG_YELLOW           "\033[33m "
#define PWN_COLOR_FG_BLUE             "\033[34m "
#define PWN_COLOR_FG_MAGENTA          "\033[35m "
#define PWN_COLOR_FG_CYAN             "\033[36m "
#define PWN_COLOR_FG_WHITE            "\033[37m "
#else
#define PWN_COLOR_RESET                 ""
#define PWN_COLOR_BOLD                  ""
#define PWN_COLOR_UNDERLINE             ""
#define PWN_COLOR_FG_BLACK              ""
#define PWN_COLOR_FG_RED                ""
#define PWN_COLOR_FG_GREEN              ""
#define PWN_COLOR_FG_YELLOW             ""
#define PWN_COLOR_FG_BLUE               ""
#define PWN_COLOR_FG_MAGENTA            ""
#define PWN_COLOR_FG_CYAN               ""
#define PWN_COLOR_FG_WHITE              ""
#endif

#define PWN_LOG_STRINGS_DEBUG           "[  DEBUG   ] "
#define PWN_LOG_STRINGS_INFO            "[  INFO    ] "
#define PWN_LOG_STRINGS_SUCCESS         "[ SUCCESS  ] "
#define PWN_LOG_STRINGS_WARN            "[   WARN   ] "
#define PWN_LOG_STRINGS_ERROR           "[  ERROR   ] "
#define PWN_LOG_STRINGS_CRITICAL        "[ CRITICAL ] "
// clang-format on


namespace pwn::Log
{
///
///@brief Define the logging level
///
enum class LogLevel : u8
{
    /// @brief  `Debug` logging level
    Debug,

    /// @brief  `Info` logging level
    Info,

    /// @brief  `Success` logging level
    Success,

    /// @brief  `Warning` logging level
    Warning,

    /// @brief  `Error` logging level
    Error,

    /// @brief  `Critical` logging level
    Critical,
};


///
/// @brief Print an output string stream as a log message
///
/// @param level
/// @param location
/// @param msg
///
void
Log(const LogLevel level, std::source_location const& location, std::ostringstream& msg);


///
/// @brief Generic logging function with prefix and arguments, for strings
/// Note: prefer using the macros `dbg`, `info`, `ok`, `warn` and `err`
///
/// @param [in] level
/// @param [in] location
/// @param [in] fmt
/// @param [in] args
///
template<typename... Args>
void
Log(const LogLevel level, std::source_location const& location, std::string_view const& fmt, Args&&... args)
{
    std::ostringstream msg;
    msg << PwnVFormat(fmt, PwnMakeFormatArgs(args...)) << '\n';
    Log(level, location, msg);
}


#ifdef PWN_BUILD_FOR_WINDOWS
///
/// @brief
///
/// @param level
/// @param location
/// @param msg
///
void
Log(const LogLevel level, std::source_location const& location, std::wostringstream& msg);


///
/// @brief Generic logging function with prefix and arguments, for wide strings
/// Note: prefer using the macros `dbg`, `info`, `ok`, `warn` and `err`
///
/// @param [in] level
/// @param [in] location
/// @param [in] fmt
/// @param [in] args
///
template<typename... Args>
void
Log(const LogLevel level, std::source_location const& location, std::wstring_view const& fmt, Args&&... args)
{
    std::wostringstream msg;
    msg << std::vformat(fmt, std::make_wformat_args(args...)) << std::endl;
    Log::Log(level, location, msg);
}

///
///@brief Format the last error (GetLastError() on Windows, errno on Linux)
///
///@param gle
///@return std::wstring
///
std::wstring
FormatLastError(const u32 gle);

///
/// @brief Basic equivalent of Linux Glibc's `perror`
///
/// @param [in] prefix a wide string view
///
void PWNAPI
perror(const std::wstring_view& prefix);


///
/// @brief Basic equivalent of Linux Glibc's `perror`
///
/// @param [in] prefix a string view
///
void PWNAPI
perror(const std::string_view& prefix);


///
/// @brief `perror` but for NTSTATUS.
///
/// @param [inout] prefix a wide string view
/// @param [inout] Status the NT status to parse
///
void PWNAPI
ntperror(const std::wstring_view& prefix, NTSTATUS Status);


///
/// @brief `perror` but for NTSTATUS.
///
/// @param [inout] prefix a string view
/// @param [inout] Status the NT status to parse
///
void PWNAPI
ntperror(const std::string_view& prefix, NTSTATUS Status);
#endif

} // namespace pwn::Log


///
/// Convenience logging macros
///
// clang-format off
#define dbg(...)    Log::Log(Log::LogLevel::Debug,    std::source_location::current(), ##__VA_ARGS__)
#define info(...)   Log::Log(Log::LogLevel::Info,     std::source_location::current(), ##__VA_ARGS__)
#define ok(...)     Log::Log(Log::LogLevel::Success,  std::source_location::current(), ##__VA_ARGS__)
#define warn(...)   Log::Log(Log::LogLevel::Warning,  std::source_location::current(), ##__VA_ARGS__)
#define err(...)    Log::Log(Log::LogLevel::Error,    std::source_location::current(), ##__VA_ARGS__)
// clang-format on
