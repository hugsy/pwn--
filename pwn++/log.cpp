
#include <stdio.h>
#include <string>
#include <vector>
#include <cassert>

#include "log.h"
#include "context.h"



namespace pwn::log
{
	HANDLE g_ConsoleMutex = INVALID_HANDLE_VALUE;

	/*++
	
	Generic logging function

	--*/
	void PWNAPI xlog(_In_ log_level_t level, _In_ const wchar_t* args_list, ...)
	{
		assert(g_ConsoleMutex != INVALID_HANDLE_VALUE);

		if ( level < pwn::context::__log_level)
			return;

		const wchar_t* prio;
		switch (level)
		{
		case log_level_t::LOG_DEBUG:      
			prio = COLOR_BOLD L"[DEBUG] " COLOR_RESET; 
			break;

		case log_level_t::LOG_INFO:       
			prio = COLOR_BOLD COLOR_FG_CYAN L"[INFO] " COLOR_RESET; 
			break;

		case log_level_t::LOG_WARNING:    
			prio = COLOR_BOLD COLOR_FG_YELLOW    L"[WARN] "     COLOR_RESET; 
			break;
		
		case log_level_t::LOG_ERROR:      
			prio = COLOR_BOLD COLOR_FG_RED       L"[ERROR] "     COLOR_RESET; 
			break;
		
		case log_level_t::LOG_CRITICAL:   
			prio = COLOR_BOLD COLOR_FG_MAGENTA   L"[CRITICAL] "    COLOR_RESET; 
			break;
		
		default:                          
			return;
		}

		size_t fmt_len = wcslen(args_list) + wcslen(prio) + 2;
		size_t total_sz = 2 * fmt_len + 2;

		auto fmt = std::make_unique<WCHAR[]>(total_sz);
		ZeroMemory(fmt.get(), total_sz);

		va_list args;
		va_start(args, args_list);

		_snwprintf_s(fmt.get(), fmt_len, _TRUNCATE, L"%s %s", prio, args_list);
		if (::WaitForSingleObject(g_ConsoleMutex, INFINITE) == WAIT_OBJECT_0)
		{
			::vfwprintf(stderr, fmt.get(), args);
			::fflush(stderr);
		}

		va_end(args);
		::ReleaseMutex(g_ConsoleMutex);
		
		if (level == log_level_t::LOG_DEBUG)
			::OutputDebugStringW(fmt.get());
	}




	/*++

	perror() style of function for Windows

	--*/
	void PWNAPI perror(_In_ const wchar_t* prefix)
	{
		auto sysMsg = std::vector<wchar_t>(1024);
		auto eNum = ::GetLastError();
		auto sysMsgSz = (DWORD)sysMsg.size();

		::FormatMessage(
			FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
			NULL,
			eNum,
			MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
			sysMsg.data(),
			sysMsgSz,
			NULL
		);

		auto sysMsgStr = std::wstring(sysMsg.begin(), sysMsg.end());
		xlog(log_level_t::LOG_ERR, L"%s, errcode=0x%x : %s", prefix, eNum, sysMsgStr.c_str());
	}


	void PWNAPI perror(_In_ const std::wstring& prefix)
	{
		perror(prefix.c_str());
	}


	void ntperror(_In_ const wchar_t* prefix, _In_ NTSTATUS Status)
	{
		auto dwDosError = ::RtlNtStatusToDosError(Status);
		auto hResult = HRESULT_FROM_WIN32(dwDosError);
		::SetLastError(hResult);
		perror(prefix);
	}

}