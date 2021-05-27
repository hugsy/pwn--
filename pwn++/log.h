#pragma once

#include "common.h"

#include <string>

#ifdef PWN_LOG_USE_COLOR
#define   COLOR_RESET               L"\033[0m"
#define   COLOR_BOLD                L"\033[1m"
#define   COLOR_UNDERLINE           L"\033[4m"
#define   COLOR_FG_BLACK            L"\033[30m"
#define   COLOR_FG_RED              L"\033[31m"
#define   COLOR_FG_GREEN            L"\033[32m"
#define   COLOR_FG_YELLOW           L"\033[33m"
#define   COLOR_FG_BLUE             L"\033[34m"
#define   COLOR_FG_MAGENTA          L"\033[35m"
#define   COLOR_FG_CYAN             L"\033[36m"
#define   COLOR_FG_WHITE            L"\033[37m"
#else
#define   COLOR_RESET
#define   COLOR_BOLD 
#define   COLOR_UNDERLINE 
#define   COLOR_FG_BLACK 
#define   COLOR_FG_RED 
#define   COLOR_FG_GREEN 
#define   COLOR_FG_YELLOW
#define   COLOR_FG_BLUE
#define   COLOR_FG_MAGENTA 
#define   COLOR_FG_CYAN
#define   COLOR_FG_WHITE
#endif


#define _PWN_LOG_LEVEL_DEBUG 0
#define _PWN_LOG_LEVEL_INFO 1
#define _PWN_LOG_LEVEL_WARN 2
#define _PWN_LOG_LEVEL_ERROR 3
#define _PWN_LOG_LEVEL_CRITICAL 4


namespace pwn::log
{
	extern PWNAPI HANDLE g_ConsoleMutex;

	enum class log_level_t
	{
		LOG_DEBUG = _PWN_LOG_LEVEL_DEBUG,
		LOG_INFO = _PWN_LOG_LEVEL_INFO,
		LOG_OK = _PWN_LOG_LEVEL_INFO,
		LOG_SUCCESS = _PWN_LOG_LEVEL_INFO,
		LOG_WARN = _PWN_LOG_LEVEL_WARN,
		LOG_WARNING = _PWN_LOG_LEVEL_WARN,
		LOG_ERR = _PWN_LOG_LEVEL_ERROR,
		LOG_ERROR = _PWN_LOG_LEVEL_ERROR,
		LOG_CRITICAL = _PWN_LOG_LEVEL_CRITICAL
	};

	void PWNAPI xlog(_In_ log_level_t level, _In_ const wchar_t* args_list, ...);
	void PWNAPI perror(_In_ const std::wstring& prefix);
	void PWNAPI perror(_In_ const wchar_t* prefix);
	void PWNAPI ntperror(_In_ const wchar_t* prefix, _In_ NTSTATUS Status);
}

#define dbg(fmt, ...)  pwn::log::xlog(pwn::log::log_level_t::LOG_DEBUG, fmt, ##__VA_ARGS__)
#define info(fmt, ...) pwn::log::xlog(pwn::log::log_level_t::LOG_INFO, fmt, ##__VA_ARGS__)
#define ok(fmt, ...)   pwn::log::xlog(pwn::log::log_level_t::LOG_SUCCESS, fmt, ##__VA_ARGS__)
#define warn(fmt, ...) pwn::log::xlog(pwn::log::log_level_t::LOG_WARNING, fmt, ##__VA_ARGS__)
#define err(fmt, ...)  pwn::log::xlog(pwn::log::log_level_t::LOG_ERROR, fmt, ##__VA_ARGS__)