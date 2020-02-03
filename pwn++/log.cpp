#include "log.h"

#include <stdio.h>

#include <string>
#include <iostream>
#include <sstream>
#include <vector>
#include <initializer_list>


namespace pwn::globals 
{
    extern HANDLE g_ConsoleMutex;
}


namespace pwn::log
{
    namespace
    {
        template <typename T>
        void _xlog(T t)
        {
            std::wcerr << t;
        }

        template <typename T, typename... Args>
        void _xlog(_In_ T t, _In_ Args... args)
        {
            std::wcerr << t;
            _xlog(args...);
            std::wcerr << std::endl;
        }
    }

    template<typename... Args>
    void xlog(_In_ log_level_t level, _In_ Args... args)
    {
#ifdef DEBUG
        if (level == LOG_DEBUG)
            return;
#endif    
    
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
   
        if (::WaitForSingleObject(pwn::globals::g_ConsoleMutex, INFINITE) == WAIT_OBJECT_0)
        {
            std::wcerr << prio << L" ";
            _xlog(args...);
            ::ReleaseMutex(pwn::globals::g_ConsoleMutex);
        }
    }
    
    template<typename... Args>
    void ok(_In_ const Args&... args)
    {
        pwn::log::xlog(log_level_t::LOG_OK, args);
    }


    template<typename... Args>
    void err(_In_ const Args&... args)
    {
        pwn::log::xlog(log_level_t::LOG_ERR, args);
    }


    /*++
    
    perror() style of function for Windows
    
    --*/
    void perror(_In_ const std::wstring& prefix)
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

        std::wstringstream wsstream;
        wsstream << prefix;
        wsstream << L", errcode=0x" << std::hex << eNum << L": ";
        wsstream << std::wstring(sysMsg.begin(), sysMsg.end());
        std::wstring msg = wsstream.str();

        //err(msg);
    }

}