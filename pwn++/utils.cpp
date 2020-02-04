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

		static const std::string base64_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

		static inline bool is_base64(unsigned char c)
		{
			return (isalnum(c) || (c == '+') || (c == '/'));
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


	std::string base64_encode(unsigned char const* bytes_to_encode, unsigned int in_len)
	{
		std::string ret;
		int i = 0;
		int j = 0;
		unsigned char char_array_3[3];
		unsigned char char_array_4[4];

		while (in_len--) {
			char_array_3[i++] = *(bytes_to_encode++);
			if (i == 3) {
				char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
				char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
				char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
				char_array_4[3] = char_array_3[2] & 0x3f;

				for (i = 0; (i < 4); i++)
					ret += base64_chars[char_array_4[i]];
				i = 0;
			}
		}

		if (i)
		{
			for (j = i; j < 3; j++)
				char_array_3[j] = '\0';

			char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
			char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
			char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
			char_array_4[3] = char_array_3[2] & 0x3f;

			for (j = 0; (j < i + 1); j++)
				ret += base64_chars[char_array_4[j]];

			while ((i++ < 3))
				ret += '=';

		}

		return ret;
	}


	std::vector<BYTE> base64_decode(_In_ std::string const& encoded_string)
	{
		size_t in_len = encoded_string.size();
		int i = 0;
		int j = 0;
		int in_ = 0;
		unsigned char char_array_4[4], char_array_3[3];
		std::vector<BYTE> ret;

		while (in_len-- && (encoded_string[in_] != '=') && is_base64(encoded_string[in_]))
		{
			char_array_4[i++] = encoded_string[in_]; in_++;
			if (i == 4)
			{
				for (i = 0; i < 4; i++)
					char_array_4[i] = base64_chars.find(char_array_4[i]) & 0xff;

				char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
				char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
				char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];

				for (i = 0; (i < 3); i++)
					ret.push_back(char_array_3[i]);
				i = 0;
			}
		}

		if (i)
		{
			for (j = i; j < 4; j++)
				char_array_4[j] = 0;

			for (j = 0; j < 4; j++)
				char_array_4[j] = base64_chars.find(char_array_4[j]) & 0xff;

			char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
			char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
			char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];

			for (j = 0; (j < i - 1); j++)
				ret.push_back(char_array_3[j]);
		}

		return ret;
	}


	std::string widestring_to_string(_In_ const std::wstring& ws)
	{
		std::string s;
		for (auto c : ws) s += (char)c;
		return s;
	}


	std::wstring string_to_widestring(_In_ const std::string& s)
	{
		std::wstring ws;
		for (auto c : s) ws += (wchar_t)c;
		return ws;
	}


	std::wstring to_widestring(_In_ const char* str)
	{
		auto s = std::string(str);
		return string_to_widestring(s);
		//const size_t str_sz = strlen(str) + 1;
		//size_t copied_size;
		//std::wstring wstr(str_sz, L'#');
		//errno_t err = ::mbstowcs_s(&copied_size, &wstr[0], str_sz, str, str_sz);
		//return wstr;
	}

}