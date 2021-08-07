#include "utils.hpp"

#include <algorithm>
#include <cstdio>
#include <ctime>
#include <iostream>
#include <sstream>
#include <type_traits>

#include "context.hpp"
#include "log.hpp"
#include "pwn.hpp"


namespace pwn::utils
{

namespace
{
// home-made ugly hexdump
// TODO: improve at some point
void
__hexdump(_In_ const u8* data, _In_ size_t size)
{
    wchar_t ascii[17] = {0};
    u32 i;
    u32 j;
    size &= 0xffffffff;

    for (i = 0; i < size; ++i)
    {
        auto c = data[i];

        if (ascii[0] == 0u)
        {
            ::wprintf(L"%04lx   ", i);
        }

        ::wprintf(L"%02X ", c);
        ascii[i % 16] = (c >= 0x20 && c <= 0x7e) ? c : '.';

        if ((i + 1) % 8 == 0 || i + 1 == size)
        {
            ::wprintf(L" ");
            if ((i + 1) % 16 == 0)
            {
                ::wprintf(L"|  %s \n", ascii);
                ::memset(ascii, 0, sizeof(ascii));
            }
            else if (i + 1 == size)
            {
                ascii[(i + 1) % 16] = '\0';
                if ((i + 1) % 16 <= 8)
                {
                    ::wprintf(L" ");
                }

                for (j = (i + 1) % 16; j < 16; ++j)
                {
                    ::wprintf(L"   ");
                }

                ::wprintf(L"|  %s \n", ascii);
            }
        }
    }
}

const std::string base64_chars =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "abcdefghijklmnopqrstuvwxyz"
    "0123456789+/";


inline bool
is_base64(unsigned char c)
{
    return ((isalnum(c) != 0) || (c == '+') || (c == '/'));
}


//
// better rand() using xorshift, stolen from gamozo
//
auto
xorshift64() -> u64
{
    auto seed = pwn::globals.m_seed;
    seed ^= seed << 13;
    seed ^= seed >> 17;
    seed ^= seed << 43;
    pwn::globals.m_seed = seed;
    return seed;
}

//
// found on SO
//
auto
xorshift128() -> u32
{
    static u32 x = 123456789;
    static u32 y = 362436069;
    static u32 z = 521288629;
    static u32 w = 88675123;
    u32 t;
    t        = x ^ (x << 11);
    x        = y;
    y        = z;
    z        = w;
    return w = w ^ (w >> 19) ^ (t ^ (t >> 8));
}


/*++

C version of the algorithm implemented in GEF

--*/
void
__create_cyclic_buffer(_In_ u32 t, _In_ u32 p, _In_ size_t dwSize, _In_ const std::string &Alphabet, _In_ u32 period, _In_ u32* aIndex, _Inout_ std::vector<u8> &lpResult)
{
    size_t dwAlphabetLen = Alphabet.size();

    if (lpResult.size() == dwSize)
    {
        return;
    }

    if (t > period)
    {
        if ((period % p) == 0)
        {
            for (uint32_t j = 1; j < p + 1; j++)
            {
                lpResult.push_back(Alphabet[aIndex[j]]);
                if (lpResult.size() == dwSize)
                {
                    return;
                }
            }
        }
    }
    else
    {
        aIndex[t] = aIndex[t - p];
        __create_cyclic_buffer(t + 1, p, dwSize, Alphabet, period, aIndex, lpResult);
        for (uint32_t j = aIndex[t - p] + 1; j < dwAlphabetLen; j++)
        {
            aIndex[t] = j;
            __create_cyclic_buffer(t + 1, t, dwSize, Alphabet, period, aIndex, lpResult);
        }
    }
}

} // namespace


void
random::seed()
{
    // g_seed = 1;
    pwn::globals.m_seed = time(nullptr);
}


auto
random::rand() -> QWORD
{
    return xorshift64();
}


auto
random::rand(_In_ u32 min, _In_ u32 max) -> u64
{
    return (xorshift64() + min) % max;
}


auto
random::byte() -> u8
{
    return random::rand() & 0xff;
}


auto
random::word() -> u16
{
    return random::rand() & 0xffff;
}


auto
random::dword() -> u32
{
    return random::rand() & 0xffffffff;
}


auto
random::qword() -> u64
{
    return random::rand();
}


auto
random::buffer(_In_ u32 length) -> std::vector<u8>
{
    std::vector<u8> buffer;
    for (u32 i = 0; i < length; i++)
    {
        buffer.push_back(random::byte());
    }
    return buffer;
}


auto
random::string(_In_ u32 length) -> std::wstring
{
    const std::wstring printable(L"0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!\"#$ % &'()*+,-./:;<=>?@[\\]^_`{|}~ ");
    std::wstring string;
    for (u32 i = 0; i < length; i++)
    {
        string += printable.at(random::rand(0, (u32)printable.length()));
    }
    return string;
}


auto
random::alnum(_In_ u32 length) -> std::wstring
{
    const std::wstring printable(L"0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ");
    std::wstring string;
    for (u32 i = 0; i < length; i++)
    {
        string += printable.at(random::rand(0, (u32)printable.length()));
    }
    return string;
}


void
hexdump(_In_ const u8* Buffer, _In_ size_t BufferSize)
{
    pwn::globals.m_console_mutex.lock();
    __hexdump(Buffer, BufferSize);
    pwn::globals.m_console_mutex.unlock();
}


void
hexdump(_In_ const std::vector<u8> &bytes)
{
    hexdump((const u8*)bytes.data(), bytes.size());
}


auto
base64_encode(_In_ std::vector<u8> const &bytes) -> std::string
{
    return base64_encode(bytes.data(), bytes.size());
}


auto
base64_encode(_In_ const u8 *bytes_to_encode, _In_ size_t in_len) -> std::string
{
    std::string ret;
    int i = 0;
    int j = 0;
    unsigned char char_array_3[3];
    unsigned char char_array_4[4];

    while ((in_len--) != 0u)
    {
        char_array_3[i++] = *(bytes_to_encode++);
        if (i == 3)
        {
            char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
            char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
            char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
            char_array_4[3] = char_array_3[2] & 0x3f;

            for (i = 0; (i < 4); i++)
            {
                ret += base64_chars[char_array_4[i]];
            }
            i = 0;
        }
    }

    if (i != 0)
    {
        for (j = i; j < 3; j++)
        {
            char_array_3[j] = '\0';
        }

        char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
        char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
        char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
        char_array_4[3] = char_array_3[2] & 0x3f;

        for (j = 0; (j < i + 1); j++)
        {
            ret += base64_chars[char_array_4[j]];
        }

        while ((i++ < 3))
        {
            ret += '=';
        }
    }

    return ret;
}


auto
base64_decode(_In_ std::string const &encoded_string) -> std::vector<u8>
{
    size_t in_len = encoded_string.size();
    int i         = 0;
    int j         = 0;
    int in_       = 0;
    unsigned char char_array_4[4];
    unsigned char char_array_3[3];
    std::vector<u8> ret;

    while (((in_len--) != 0u) && (encoded_string[in_] != '=') && is_base64(encoded_string[in_]))
    {
        char_array_4[i++] = encoded_string[in_];
        in_++;
        if (i == 4)
        {
            for (i = 0; i < 4; i++)
            {
                char_array_4[i] = base64_chars.find(char_array_4[i]) & 0xff;
            }

            char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
            char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
            char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];

            for (i = 0; (i < 3); i++)
            {
                ret.push_back(char_array_3[i]);
            }
            i = 0;
        }
    }

    if (i != 0)
    {
        for (j = i; j < 4; j++)
        {
            char_array_4[j] = 0;
        }

        for (j = 0; j < 4; j++)
        {
            char_array_4[j] = base64_chars.find(char_array_4[j]) & 0xff;
        }

        char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
        char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
        char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];

        for (j = 0; (j < i - 1); j++)
        {
            ret.push_back(char_array_3[j]);
        }
    }

    return ret;
}


auto
widestring_to_string(_In_ const std::wstring &ws) -> std::string
{
    std::string s;
    for (auto c : ws)
    {
        s += (char)c;
    }
    return s;
}


auto
string_to_widestring(_In_ const std::string &s) -> std::wstring
{
    std::wstring ws;
    for (auto c : s)
    {
        ws += (wchar_t)c;
    }
    return ws;
}


auto
to_widestring(_In_ const char *str) -> std::wstring
{
    return string_to_widestring(std::string(str));
}


auto
split(_In_ const std::wstring &ws, _In_ const wchar_t delim = L' ') -> std::vector<std::wstring>
{
    std::vector<std::wstring> out;
    std::wstringstream wss(ws);
    std::wstring token;

    while (std::getline(wss, token, delim))
    {
        out.push_back(token);
    }

    return out;
}


auto
join(_In_ const std::vector<std::wstring> &args) -> std::wstring // todo: replace w/ c++17 variadic
{
    std::wstring res;
    for(auto const& x : args)
        res += std::wstring{x};
    return res;
}


auto
path::abspath(_In_ const std::wstring &path) -> std::wstring
{
    auto res = std::wstring();
    res.resize(MAX_PATH + 1);

    ::GetFullPathNameW(path.c_str(), MAX_PATH, &res[0], nullptr);
    return res;
}


auto
startswith(_In_ const std::string &str, _In_ const std::string &pattern) -> bool
{
    return static_cast<bool>(str.size() >= pattern.size() && str.compare(0, pattern.size(), pattern) == 0);
}


auto
startswith(_In_ const std::wstring &str, _In_ const std::wstring &pattern) -> bool
{
    return static_cast<bool>(str.size() >= pattern.size() && str.compare(0, pattern.size(), pattern) == 0);
}


auto
endswith(_In_ const std::string &str, _In_ const std::string &pattern) -> bool
{
    return static_cast<bool>(str.size() >= pattern.size() && str.compare(str.size() - pattern.size(), pattern.size(), pattern) == 0);
}


auto
endswith(_In_ const std::wstring &str, _In_ const std::wstring &pattern) -> bool
{
    return static_cast<bool>(str.size() >= pattern.size() && str.compare(str.size() - pattern.size(), pattern.size(), pattern) == 0);
}


auto
wstring_to_bytes(_In_ std::wstring const &str) -> std::vector<u8>
{
    std::vector<u8> out;
    for (wchar_t i : str)
    {
        out.push_back((u8)i);
        out.push_back(0x00);
    }
    return out;
}

auto
string_to_bytes(_In_ std::string const &str) -> std::vector<u8>
{
    std::vector<u8> out;
    std::transform(
        str.begin(),
        str.end(),
        std::back_inserter(out), [](char const c) { return c; }
    );
    return out;
}


/*++

Create a DeBruijn cyclic pattern

 --*/
auto
cyclic(_In_ u32 dwSize, _In_ u32 dwPeriod, _Out_ std::vector<u8> &buffer) -> bool
{
    const std::string lpAlphabet("abcdefghijklmnopqrstuvwxyz");
    buffer.clear();

    auto aIndex = std::make_unique<u32[]>(lpAlphabet.size() * dwPeriod);
    __create_cyclic_buffer(
        1,
        1,
        dwSize,
        lpAlphabet,
        dwPeriod,
        aIndex.get(),
        buffer
    );
    return true;
}


auto
cyclic(_In_ u32 dwSize, _In_ u32 dwPeriod) -> std::vector<u8>
{
    std::vector<u8> buffer;
    if (cyclic(dwSize, dwPeriod, buffer) != 0)
    {
        return buffer;
    }
    throw std::runtime_error("cyclic failed");
}


auto
cyclic(_In_ u32 dwSize, _Out_ std::vector<u8> &buffer) -> bool
{
    return cyclic(dwSize, pwn::context::ptrsize, buffer);
}


auto
cyclic(_In_ u32 dwSize) -> std::vector<u8>
{
    std::vector<u8> buffer;
    if (cyclic(dwSize, pwn::context::ptrsize, buffer) != 0)
    {
        return buffer;
    }
    throw std::runtime_error("cyclic failed");
}


/*++

C++17 port of flat() from pwnlib

--*/
template <typename T>
auto
__pack(_In_ T v) -> std::vector<u8>
{
    std::vector<u8> out;
    pwn::context::endianess_t endian = pwn::context::endian;
    if (endian == pwn::context::endianess_t::little)
    {
        for (int i = sizeof(T) - 1; i >= 0; i--)
        {
            out.push_back((v >> (8 * i)) & 0xff);
        }
    }
    /*
    else
    {
        TODO: big endian
    }
    */
    return out;
}

auto
p8(_In_ u8 v) -> std::vector<u8>
{
    return __pack(v);
}
auto
p16(_In_ WORD v) -> std::vector<u8>
{
    return __pack(v);
}
auto
p32(_In_ u32 v) -> std::vector<u8>
{
    return __pack(v);
}
auto
p64(_In_ QWORD v) -> std::vector<u8>
{
    return __pack(v);
}


auto
__flatten(_In_ const flattenable_t &v) -> std::vector<u8>
{
    if (const auto ptr = std::get_if<0>(&v))
    {
        std::string s(*ptr);
        return std::vector<u8>(s.begin(), s.end());
    }

    if (const auto ptr = std::get_if<1>(&v))
    {
        const std::wstring &s(*ptr);
        return wstring_to_bytes(s);
    }

    if (const auto ptr = std::get_if<2>(&v))
    {
        return std::get<2>(v);
    }

    return std::vector<u8>();
}


auto
flatten(_In_ const std::vector<flattenable_t> &args) -> std::vector<u8>
{
    std::vector<u8> flat;
    for (const auto &arg : args)
    {
        auto tmp = __flatten(arg);
        flat.insert(flat.end(), tmp.begin(), tmp.end());
    }

    return flat;
}


void
pause()
{
    dbg(L"Pausing, press enter to resume...\n");
    std::cin.get();
}

} // namespace pwn::utils
