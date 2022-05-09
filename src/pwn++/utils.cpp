#include "utils.hpp"

#include <algorithm>
#include <cstdio>
#include <ctime>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <type_traits>

#include "context.hpp"
#include "log.hpp"
#include "pwn.hpp"

extern struct pwn::globals_t pwn::globals;


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

    for ( i = 0; i < size; ++i )
    {
        auto c = data[i];

        if ( ascii[0] == 0u )
        {
            std::wcout << std::setfill((wchar_t)'0') << std::setw(4) << std::noshowbase << std::hex << (int)i << "   ";
        }

        std::wcout << std::setfill((wchar_t)'0') << std::setw(2) << std::uppercase << std::noshowbase << std::hex
                   << (int)c << " ";
        ascii[i % 16] = (c >= 0x20 && c <= 0x7e) ? c : '.';

        if ( (i + 1) % 8 == 0 || i + 1 == size )
        {
            std::wcout << " ";
            if ( (i + 1) % 16 == 0 )
            {
                std::wcout << "|  " << ascii << std::endl;
                ::memset(ascii, 0, sizeof(ascii));
            }
            else if ( i + 1 == size )
            {
                ascii[(i + 1) % 16] = '\0';
                if ( (i + 1) % 16 <= 8 )
                {
                    std::wcout << " ";
                }
                for ( j = (i + 1) % 16; j < 16; ++j )
                {
                    std::wcout << "   ";
                }
                std::wcout << "|  " << ascii << std::endl;
            }
        }
    }

    std::wcout << std::flush;
}

const std::string b64_charset =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "abcdefghijklmnopqrstuvwxyz"
    "0123456789+/";


const std::vector<i8> b64_inverted_table = {
    62, -1, -1, -1, 63, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, -1, -1, -1, -1, -1, -1, -1, 0,  1,  2,  3,  4,
    5,  6,  7,  8,  9,  10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, -1, -1, -1, -1, -1, -1,
    26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51};


inline auto
b64_is_valid_char(unsigned char c) -> bool
{
    return ((isalnum(c) != 0) || (c == '+') || (c == '/') || (c == '='));
}


inline auto
b64_encoded_size(size_t inlen) -> size_t
{
    size_t ret = inlen;
    if ( inlen % 3 != 0 )
        ret += 3 - (inlen % 3);
    ret /= 3;
    ret *= 4;
    return ret;
}

inline auto
b64_decoded_size(const char* in) -> size_t
{
    if ( in == nullptr )
        return 0;

    size_t len = strlen(in);
    size_t ret = len / 4 * 3;
    for ( size_t i = len; (i--) > 0; )
    {
        if ( in[i] == '=' )
        {
            ret--;
        }
        else
        {
            break;
        }
    }
    return ret;
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

/*
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
*/

/*++

C version of the algorithm implemented in GEF

--*/
void
__create_cyclic_buffer(
    _In_ u32 t,
    _In_ u32 p,
    _In_ size_t dwSize,
    _In_ const std::string& Alphabet,
    _In_ u32 period,
    _In_ u32* aIndex,
    _Inout_ std::vector<u8>& lpResult)
{
    size_t dwAlphabetLen = Alphabet.size();

    if ( lpResult.size() == dwSize )
    {
        return;
    }

    if ( t > period )
    {
        if ( (period % p) == 0 )
        {
            for ( uint32_t j = 1; j < p + 1; j++ )
            {
                lpResult.push_back(Alphabet[aIndex[j]]);
                if ( lpResult.size() == dwSize )
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
        for ( uint32_t j = aIndex[t - p] + 1; j < dwAlphabetLen; j++ )
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
random::rand() -> u64
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
    for ( u32 i = 0; i < length; i++ )
    {
        buffer.push_back(random::byte());
    }
    return buffer;
}


auto
random::string(_In_ u32 length) -> std::wstring
{
    const std::wstring printable(L"" PWN_UTILS_PRINTABLE_CHARSET);
    std::wstring string;
    for ( u32 i = 0; i < length; i++ )
    {
        string += printable.at(random::rand(0, (u32)printable.length()));
    }
    return string;
}


auto
random::alnum(_In_ u32 length) -> std::wstring
{
    const std::wstring printable(L"" PWN_UTILS_ALNUM_CHARSET);
    std::wstring string;
    for ( u32 i = 0; i < length; i++ )
    {
        string += printable.at(random::rand(0, (u32)printable.length()));
    }
    return string;
}


void
hexdump(_In_ const u8* Buffer, _In_ size_t BufferSize)
{
    std::lock_guard<std::mutex> guard(pwn::globals.m_console_mutex);
    __hexdump(Buffer, BufferSize);
}


void
hexdump(_In_ const std::vector<u8>& bytes)
{
    hexdump((const u8*)bytes.data(), bytes.size());
}


auto
base64_encode(_In_ std::vector<u8> const& bytes) -> std::string
{
    return base64_encode(bytes.data(), bytes.size());
}


auto
base64_encode(_In_ const u8* in, _In_ size_t len) -> std::string
{
    if ( in == nullptr || len == 0 )
        throw std::runtime_error("invalid input");

    size_t elen        = b64_encoded_size(len);
    auto output_buffer = std::make_unique<u8[]>(elen + 1);
    auto out           = output_buffer.get();
    memset(out, 0, elen + 1);

    for ( size_t i = 0, j = 0; i < len; i += 3, j += 4 )
    {
        u32 v = in[i];
        v     = i + 1 < len ? v << 8 | in[i + 1] : v << 8;
        v     = i + 2 < len ? v << 8 | in[i + 2] : v << 8;

        out[j]     = b64_charset[(v >> 18) & 0x3F];
        out[j + 1] = b64_charset[(v >> 12) & 0x3F];
        out[j + 2] = (i + 1 < len) ? b64_charset[(v >> 6) & 0x3F] : '=';
        out[j + 3] = (i + 2 < len) ? b64_charset[v & 0x3F] : '=';
    }

    return std::string(reinterpret_cast<char*>(out), elen);
}


auto
base64_decode(_In_ std::string const& in) -> std::optional<std::vector<u8>>
{
    size_t len    = in.size();
    size_t outlen = b64_decoded_size(in.c_str());

    if ( !len || !outlen || len % 4 != 0 )
        return std::nullopt;

    for ( size_t i = 0; i < len; i++ )
    {
        if ( !b64_is_valid_char(in[i]) )
        {
            return std::nullopt;
        }
    }

    std::vector<u8> out(outlen, 0);
    for ( size_t i = 0, j = 0; i < len; i += 4, j += 3 )
    {
        int v = b64_inverted_table[in[i] - 43];
        v     = (v << 6) | b64_inverted_table[in[i + 1] - 43];
        v     = in[i + 2] == '=' ? v << 6 : (v << 6) | b64_inverted_table[in[i + 2] - 43];
        v     = in[i + 3] == '=' ? v << 6 : (v << 6) | b64_inverted_table[in[i + 3] - 43];

        out[j] = (v >> 16) & 0xFF;
        if ( in[i + 2] != '=' )
            out[j + 1] = (v >> 8) & 0xFF;
        if ( in[i + 3] != '=' )
            out[j + 2] = v & 0xFF;
    }

    return out;
}


auto
to_string(_In_ std::wstring const& wstr) -> std::string
{
    std::string out;
    std::transform(
        wstr.begin(),
        wstr.end(),
        std::back_inserter(out),
        [](wchar_t const c)
        {
            return static_cast<char>(c);
        });
    return out;
}


auto
to_widestring(_In_ std::string const& str) -> std::wstring
{
    std::wstring out;
    std::transform(
        str.begin(),
        str.end(),
        std::back_inserter(out),
        [](char const c)
        {
            return static_cast<wchar_t>(c);
        });
    return out;
}


auto
split(_In_ const std::wstring& ws, _In_ const wchar_t delim = L' ') -> std::vector<std::wstring>
{
    std::vector<std::wstring> out;
    std::wstringstream wss(ws);
    std::wstring token;

    while ( std::getline(wss, token, delim) )
    {
        out.push_back(token);
    }

    return out;
}


auto
join(_In_ const std::vector<std::wstring>& args) -> std::wstring // todo: replace w/ c++17 variadic
{
    std::wstring res;
    for ( auto const& x : args )
        res += std::wstring {x};
    return res;
}


template<typename T, typename N>
auto static inline strippable_string(_In_ T const& in, _In_ N const& chars_to_strip) -> T
{
    T out {in};
    for ( auto const& c : out )
    {
        std::erase_if(
            out,
            [&c](auto const& x)
            {
                return x == c;
            });
    }
    return out;
}


auto
strip(_In_ std::wstring const& str) -> std::wstring
{
    const std::array<wchar_t, 3> chars_to_strip = {' ', '\r', '\n'};
    return strippable_string(str, chars_to_strip);
}


auto
strip(_In_ std::string const& str) -> std::string
{
    const std::array<char, 3> chars_to_strip = {' ', '\r', '\n'};
    return strippable_string(str, chars_to_strip);
}


auto
path::abspath(_In_ const std::wstring& path) -> std::wstring
{
#if defined(__PWNLIB_WINDOWS_BUILD__)
    auto res = std::wstring();
    res.resize(MAX_PATH + 1);
    ::GetFullPathNameW(path.c_str(), MAX_PATH, &res[0], nullptr);
    return res;
#elif defined(__PWNLIB_LINUX_BUILD__)
    auto out = realpath(to_string(path).c_str(), nullptr);
    return to_widestring(out);
#endif
}


auto
startswith(_In_ const std::string& str, _In_ const std::string& pattern) -> bool
{
    return static_cast<bool>(str.size() >= pattern.size() && str.compare(0, pattern.size(), pattern) == 0);
    return str.starts_with(pattern.c_str());
}


auto
startswith(_In_ const std::wstring& str, _In_ const std::wstring& pattern) -> bool
{
    // return static_cast<bool>(str.size() >= pattern.size() && str.compare(0, pattern.size(), pattern) == 0);
    return str.starts_with(pattern.c_str());
}


auto
endswith(_In_ const std::string& str, _In_ const std::string& pattern) -> bool
{
    // return static_cast<bool>(
    //     str.size() >= pattern.size() && str.compare(str.size() - pattern.size(), pattern.size(), pattern) == 0);
    return str.ends_with(pattern.c_str());
}


auto
endswith(_In_ const std::wstring& str, _In_ const std::wstring& pattern) -> bool
{
    // return static_cast<bool>(str.size() >= pattern.size() && str.compare(str.size() - pattern.size(), pattern.size(),
    // pattern) == 0);
    return str.ends_with(pattern.c_str());
}


auto
wstring_to_bytes(_In_ std::wstring const& str) -> std::vector<u8>
{
    std::vector<u8> out;
    for ( wchar_t i : str )
    {
        out.push_back((u8)i);
        out.push_back(0x00);
    }
    return out;
}

auto
string_to_bytes(_In_ std::string const& str) -> std::vector<u8>
{
    std::vector<u8> out;
    std::transform(
        str.begin(),
        str.end(),
        std::back_inserter(out),
        [](char const c)
        {
            return c;
        });
    return out;
}


/**
 * @brief Create a DeBruijn cyclic pattern
 *
 * @param dwSize
 * @param dwPeriod
 * @param buffer
 * @return true
 * @return false
 */
auto
cyclic(_In_ u32 dwSize, _In_ u32 dwPeriod, _Out_ std::vector<u8>& buffer) -> bool
{
    const std::string lpAlphabet("abcdefghijklmnopqrstuvwxyz");
    buffer.clear();

    auto aIndex = std::make_unique<u32[]>(lpAlphabet.size() * dwPeriod);
    __create_cyclic_buffer(1, 1, dwSize, lpAlphabet, dwPeriod, aIndex.get(), buffer);
    return true;
}


auto
cyclic(_In_ u32 dwSize, _In_ u32 dwPeriod) -> std::vector<u8>
{
    std::vector<u8> buffer;
    if ( cyclic(dwSize, dwPeriod, buffer) != 0 )
    {
        return buffer;
    }
    throw std::runtime_error("cyclic failed");
}


auto
cyclic(_In_ u32 dwSize, _Out_ std::vector<u8>& buffer) -> bool
{
    return cyclic(dwSize, pwn::globals.ptrsize, buffer);
}


auto
cyclic(_In_ u32 dwSize) -> std::vector<u8>
{
    std::vector<u8> buffer;
    if ( cyclic(dwSize, pwn::globals.ptrsize, buffer) != 0 )
    {
        return buffer;
    }
    throw std::runtime_error("cyclic failed");
}


/**
 * @brief C++17 port of flat() from pwnlib
 *
 * @tparam T
 * @param v
 * @return std::vector<u8>
 */
template<typename T>
auto
__pack(_In_ T v) -> std::vector<u8>
{
    std::vector<u8> out;
    if ( pwn::globals.endianess == Endianess::little )
    {
        for ( auto i = sizeof(T) - 1; i >= 0; i-- )
        {
            out.push_back((v >> (8 * i)) & 0xff);
        }
    }
    else
    {
        for ( auto i = 0; i < sizeof(T); i++ )
        {
            out.push_back((v >> (8 * i)) & 0xff);
        }
    }

    return out;
}

auto
p8(_In_ u8 v) -> std::vector<u8>
{
    return __pack(v);
}
auto
p16(_In_ u16 v) -> std::vector<u8>
{
    return __pack(v);
}
auto
p32(_In_ u32 v) -> std::vector<u8>
{
    return __pack(v);
}
auto
p64(_In_ u64 v) -> std::vector<u8>
{
    return __pack(v);
}


auto
__flatten(_In_ const flattenable_t& v) -> std::vector<u8>
{
    if ( const auto ptr = std::get_if<0>(&v) )
    {
        std::string s(*ptr);
        return std::vector<u8>(s.begin(), s.end());
    }

    if ( const auto ptr = std::get_if<1>(&v) )
    {
        const std::wstring& s(*ptr);
        return wstring_to_bytes(s);
    }

    if ( const auto ptr = std::get_if<2>(&v) )
    {
        return std::get<2>(v);
    }

    return std::vector<u8>();
}


auto
flatten(_In_ const std::vector<flattenable_t>& args) -> std::vector<u8>
{
    std::vector<u8> flat;
    for ( const auto& arg : args )
    {
        auto tmp = __flatten(arg);
        flat.insert(flat.end(), tmp.begin(), tmp.end());
    }

    return flat;
}


void
pause()
{
    dbg(L"Pausing, press enter to resume...");
    std::cin.get();
}


void
debugbreak()
{
    dbg(L"Breakpointing...");
    DebugBreak();
}

} // namespace pwn::utils
