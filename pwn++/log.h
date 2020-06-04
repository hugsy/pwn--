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


namespace pwn::log
{
	extern PWNAPI HANDLE g_ConsoleMutex;

	enum class log_level_t
	{
		LOG_DEBUG = 0,
		LOG_INFO = 1,
		LOG_OK = 2,
		LOG_SUCCESS = 2,
		LOG_WARN = 3,
		LOG_WARNING = 3,
		LOG_ERR = 4,
		LOG_ERROR = 4,
		LOG_CRITICAL = 5
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