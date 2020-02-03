#pragma once

#include <Windows.h>

#include <string>


namespace pwn::log
{
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


	template<typename... Args>
	void xlog(_In_ log_level_t level, _In_ Args... args);

	template<typename... Args>
	void ok(_In_ const Args&... args);

	template<typename... Args>
	void err(_In_ const Args&... args);

	void perror(_In_ const std::wstring& prefix);

}
