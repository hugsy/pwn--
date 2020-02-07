#include "utils.h"
#include "log.h"
#include "context.h"

#include <stdio.h>
#include <type_traits>
#include <iostream>


extern HANDLE pwn::log::g_ConsoleMutex;

QWORD g_seed = 0;


namespace pwn::utils
{
	namespace
	{
		// home-made ugly hexdump
		// TODO: improve at some point       
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


		//
		// better rand() using xorshift, stolen from gamozo
		//
		QWORD xorshift64(void)
		{
			g_seed ^= g_seed << 13;
			g_seed ^= g_seed >> 17;
			g_seed ^= g_seed << 43;
			return g_seed;
		}

		//
		// found on SO
		// 
		DWORD xorshift128(void)
		{
			static DWORD x = 123456789;
			static DWORD y = 362436069;
			static DWORD z = 521288629;
			static DWORD w = 88675123;
			DWORD t;
			t = x ^ (x << 11);
			x = y;
			y = z;
			z = w;
			return w = w ^ (w >> 19) ^ (t ^ (t >> 8));
		}
	
	
		/*++

		C version of the algorithm implemented in GEF

		--*/
		void __create_cyclic_buffer(
			_In_ DWORD t,
			_In_ DWORD p,
			_In_ SIZE_T dwSize,
			_In_ const std::string& Alphabet,
			_In_ DWORD period,
			_In_ PDWORD aIndex,
			_Inout_ std::vector<BYTE>& lpResult
		)
		{
			SIZE_T dwAlphabetLen = Alphabet.size();

			if ( lpResult.size() == dwSize )
				return;

			if ( t > period )
			{
				if ( (period % p) == 0 )
				{
					for ( uint32_t j = 1; j < p + 1; j++ )
					{
						lpResult.push_back(Alphabet[aIndex[j]]);
						if ( lpResult.size() == dwSize )
							return;
					}
				}
			}
			else
			{
				aIndex[t] = aIndex[t - p];
				__create_cyclic_buffer(t + 1, p, dwSize, Alphabet, period, aIndex, lpResult);
				for ( uint32_t j = aIndex[t - p] + 1; j < dwAlphabetLen; j++ )
				{
					aIndex[t] = j;
					__create_cyclic_buffer(t + 1, t, dwSize, Alphabet, period, aIndex, lpResult);
				}
			}
			return;
		}

	}
	

	QWORD rand(void)
	{
		return xorshift64();
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
		return string_to_widestring(std::string(str));
	}




	/*++

	Create a DeBruijn cyclic pattern

	 --*/
	BOOL cyclic(_In_ DWORD dwSize, _In_ DWORD dwPeriod, _Out_ std::vector<BYTE>& buffer)
	{
		const std::string lpAlphabet("abcdefghijklmnopqrstuvwxyz");
		buffer.clear();

		auto aIndex = std::make_unique<DWORD[]>(lpAlphabet.size() * dwPeriod);
		__create_cyclic_buffer(1, 1, dwSize, lpAlphabet, dwPeriod, aIndex.get(), buffer);
		return TRUE;
	}


	BOOL cyclic(_In_ DWORD dwSize, _Out_ std::vector<BYTE>& buffer)
	{
		return cyclic(dwSize, pwn::context::ptrsize, buffer);
	}


	/*++
	
	C++17 port of flat() from pwnlib

	--*/
	/*
	template<typename T>
	std::vector<BYTE> flat(T v)
	{
		if constexpr (std::is_same_v<T, std::string>)
			return std::vector<BYTE>(v.begin(), v.end());

		throw std::runtime_error("Unknown type to flatten");
	}


	template<typename T, typename... Args>
	std::vector<BYTE> flat(T first, Args... args)
	{
		std::vector<BYTE> head = flat(first);
		std::vector<BYTE> tail = flat(args);
		head.insert(head.end(), tail.begin(), tail.end());
		return head;
	}
	*/
	template<typename T>
	std::vector<BYTE> __pack(_In_ T v)
	{
		std::vector<BYTE> out;
		for (int i = sizeof(T) - 1; i >= 0; i--)
			out.push_back((v >> (8 * i)) & 0xff);
		return out;
	}

	std::vector<BYTE> p16(_In_  WORD v) { return __pack(v); }
	std::vector<BYTE> p32(_In_ DWORD v) { return __pack(v); }
	std::vector<BYTE> p64(_In_ QWORD v) { return __pack(v); }


	template<typename T>
	std::vector<BYTE> __flatten(_In_ T v)
	{
		if constexpr (std::is_same_v<T, std::string>)
			return std::vector<BYTE>(v.begin(), v.end());

		if constexpr (std::is_same_v<T, DWORD>)
			return p32(v);

		if constexpr (std::is_same_v<T, QWORD>)
			return p64(v);

		return std::vector<BYTE>();
		//throw std::runtime_error("Unknown type to flatten");
	}


	std::vector<BYTE> flatten(_In_ std::vector<flattenable_t>& args)
	{
		std::vector<BYTE> flat;
		for (const auto& arg: args)
		{
			auto tmp = __flatten(arg);
			flat.insert(flat.end(), tmp.begin(), tmp.end());
		}

		return flat;
	}
}