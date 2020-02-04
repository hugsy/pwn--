#include "utils.h"
#include "log.h"

#include <stdio.h>


extern HANDLE pwn::log::g_ConsoleMutex;


namespace pwn::utils
{
    namespace
    {
        /**
        home-made ugly hexdump
        TODO: improve
        */
        void __hexdump(_In_ const PBYTE data, _In_ SIZE_T size)
        {
            WCHAR ascii[17] = { 0, };
            SIZE_T i, j;

            for (i = 0; i < size; ++i) {
                BYTE c = *((PCHAR)data + i);

                if (!ascii[0])
                    ::wprintf(L"%04llx   ", i);

                ::wprintf(L"%02X ", c);
                ascii[i % 16] = (c >= 0x20 && c <= 0x7e) ? c : '.';

                if ((i + 1) % 8 == 0 || i + 1 == size) {
                    ::wprintf(L" ");
                    if ((i + 1) % 16 == 0)
                    {
                        ::wprintf(L"|  %s \n", ascii);
                        ::ZeroMemory(ascii, sizeof(ascii));
                    }
                    else if (i + 1 == size)
                    {
                        ascii[(i + 1) % 16] = '\0';
                        if ((i + 1) % 16 <= 8)
                            ::wprintf(L" ");

                        for (j = (i + 1) % 16; j < 16; ++j)
                            ::wprintf(L"   ");

                        ::wprintf(L"|  %s \n", ascii);
                    }
                }
            }
        }
    }


    void hexdump(_In_ const PBYTE Buffer, _In_ SIZE_T BufferSize)
    {
        if (::WaitForSingleObject(pwn::log::g_ConsoleMutex, INFINITE) == WAIT_OBJECT_0)
        {
            __hexdump(Buffer, BufferSize);
            ::ReleaseMutex(pwn::log::g_ConsoleMutex);
        }
    }

    void hexdump(_In_ const std::vector<BYTE>& bytes)
    {
        hexdump((const PBYTE)bytes.data(), bytes.size());
    }
}