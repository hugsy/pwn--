#pragma once

#include "common.h"

#include <string>


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
}

#define dbg(fmt, ...)  xlog(log_level_t::LOG_DEBUG, fmt, ##__VA_ARGS__)
#define info(fmt, ...) xlog(log_level_t::LOG_INFO, fmt, ##__VA_ARGS__)
#define ok(fmt, ...)   xlog(log_level_t::LOG_SUCCESS, fmt, ##__VA_ARGS__)
#define warn(fmt, ...) xlog(log_level_t::LOG_WARNING, fmt, ##__VA_ARGS__)
#define err(fmt, ...)  xlog(log_level_t::LOG_ERROR, fmt, ##__VA_ARGS__)