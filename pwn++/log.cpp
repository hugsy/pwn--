#include <stdio.h>
#include <string>
#include <vector>
#include <cassert>

#include "log.h"


namespace pwn::log
{
    PWNAPI HANDLE g_ConsoleMutex = INVALID_HANDLE_VALUE;

    /*++
    
    Generic logging function

    --*/
    void PWNAPI xlog(_In_ log_level_t level, _In_ const wchar_t* args_list, ...)
    {
#ifdef DEBUG
        if (level == LOG_DEBUG)
            return;
#endif    

        assert(g_ConsoleMutex != INVALID_HANDLE_VALUE);

        const wchar_t* prio;
        switch (level)
        {
        case log_level_t::LOG_DEBUG:      prio = L"[DEBUG] "; break;
        case log_level_t::LOG_INFO:       prio = L"[*] "; break;
        case log_level_t::LOG_SUCCESS:    prio = L"[+] "; break;
        case log_level_t::LOG_WARNING:    prio = L"[!] "; break;
        case log_level_t::LOG_ERROR:      prio = L"[-] "; break;
        case log_level_t::LOG_CRITICAL:   prio = L"/!\\ "; break;
        default:                          return;
        }

        size_t fmt_len = wcslen(args_list) + wcslen(prio) + 2;
        size_t total_sz = 2 * fmt_len + 2;
        PWCHAR fmt = (PWCHAR)LocalAlloc(LPTR, total_sz);
        if (!fmt)
            return;

        ZeroMemory(fmt, 2 * fmt_len + 2);

        va_list args;
        va_start(args, args_list);

        _snwprintf_s(fmt, fmt_len, _TRUNCATE, L"%s %s", prio, args_list);
        if (::WaitForSingleObject(g_ConsoleMutex, INFINITE) == WAIT_OBJECT_0)
        {
            ::vfwprintf(stderr, fmt, args);
            ::fflush(stderr);
        }

        va_end(args);
        ::ReleaseMutex(g_ConsoleMutex);
        ::LocalFree(fmt);
    }




    /*++

    perror() style of function for Windows

    --*/
    void PWNAPI perror(_In_ const wchar_t* prefix)
    {
        auto sysMsg = std::vector<wchar_t>(1024);
        DWORD eNum = ::GetLastError(), sysMsgSz = (DWORD)sysMsg.size();

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
}