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


#define PWN_UTILS_LOWER_CHARSET "abcdefghijklmnopqrstuvwxyz"
#define PWN_UTILS_UPPER_CHARSET "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
#define PWN_UTILS_DIGITS_CHARSET "0123456789"
#define PWN_UTILS_UPPER_LOWER_CHARSET PWN_UTILS_LOWER_CHARSET PWN_UTILS_UPPER_CHARSET
#define PWN_UTILS_ALNUM_CHARSET PWN_UTILS_UPPER_LOWER_CHARSET PWN_UTILS_DIGITS_CHARSET
#define PWN_UTILS_PRINTABLE_CHARSET PWN_UTILS_ALNUM_CHARSET "!\"#$ % &'()*+,-./:;<=>?@[\\]^_`{|}~ "


template<std::integral... Args>
bool
all(Args... args)
{
    return (... && args);
}


template<std::integral... Args>
bool
any(Args... args)
{
    return (... || args);
}


template<std::integral... Args>
bool
none(Args... args)
{
    return not(... || args);
}


namespace pwn::utils
{

namespace
{
// home-made ugly hexdump
// TODO: improve at some point
std::wostringstream
__hexdump(const u8* data, const usize sz)
{
    std::wostringstream wos;
    wchar_t ascii[17] = {0};
    const u32 size    = sz & 0xffffffff;

    for ( u32 i = 0; i < size; ++i )
    {
        auto const c = data[i];

        if ( ascii[0] == 0u )
        {
            wos << std::setfill((wchar_t)'0') << std::setw(4) << std::noshowbase << std::hex << (int)i << "   ";
        }

        wos << std::setfill((wchar_t)'0') << std::setw(2) << std::uppercase << std::noshowbase << std::hex << (int)c
            << " ";
        ascii[i % 16] = (c >= 0x20 && c <= 0x7e) ? c : '.';

        if ( (i + 1) % 8 == 0 || i + 1 == size )
        {
            wos << " ";
            if ( (i + 1) % 16 == 0 )
            {
                wos << "|  " << ascii << std::endl;
                ::memset(ascii, 0, sizeof(ascii));
            }
            else if ( i + 1 == size )
            {
                ascii[(i + 1) % 16] = '\0';
                if ( (i + 1) % 16 <= 8 )
                {
                    wos << " ";
                }
                for ( u32 j = (i + 1) % 16; j < 16; ++j )
                {
                    wos << "   ";
                }
                wos << "|  " << ascii << std::endl;
            }
        }
    }

    return wos;
}

constexpr std::string_view b64_charset =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "abcdefghijklmnopqrstuvwxyz"
    "0123456789+/";


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


/*++

C version of the algorithm implemented in GEF

--*/
void
__create_cyclic_buffer(
    _In_ u32 t,
    _In_ u32 p,
    _In_ usize dwSize,
    _In_ const std::string& Alphabet,
    _In_ u32 period,
    _In_ u32* aIndex,
    _Inout_ std::vector<u8>& lpResult)
{
    usize dwAlphabetLen = Alphabet.size();

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
random::seed(std::optional<u64> seed)
{
    dbg(L"Re-seeding globals");

    if ( seed )
    {
        pwn::globals.m_seed = seed.value();
    }
    else
    {
        pwn::globals.m_seed = time(nullptr);
    }
}


auto
random::rand() -> u64
{
    return xorshift64();
}


auto
random::rand(u64 const max, u64 const min) noexcept -> u64
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
hexdump(const u8* Buffer, const usize BufferSize)
{
    auto hexstr = __hexdump(Buffer, BufferSize);

    {
        std::lock_guard<std::mutex> guard(pwn::globals.m_console_mutex);
        std::wcout << hexstr.str() << std::endl;
    }
}


void
hexdump(const std::vector<u8>& bytes)
{
    hexdump((const u8*)bytes.data(), bytes.size());
}


auto
base64_encode(std::vector<u8> const& bytes) -> Result<std::string>
{
    return base64_encode(bytes.data(), bytes.size());
}


auto
base64_encode(const u8* in, const usize len) -> Result<std::string>
{
    auto encoded_size = [](const usize inlen) -> usize
    {
        usize ret = inlen;
        if ( inlen % 3 != 0 )
            ret += 3 - (inlen % 3);
        ret /= 3;
        ret *= 4;
        return ret;
    };

    if ( in == nullptr || len == 0 )
        return Err(ErrorCode::InvalidParameter);

    const usize elen   = encoded_size(len);
    auto output_buffer = std::make_unique<u8[]>(elen + 1);
    auto out           = output_buffer.get();
    memset(out, 0, elen + 1);

    for ( usize i = 0, j = 0; i < len; i += 3, j += 4 )
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
base64_decode(std::string_view const& in) -> Result<std::vector<u8>>
{
    const std::array<i8, 80> b64_inverted_table = {
        62, -1, -1, -1, 63, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, -1, -1, -1, -1, -1, -1, -1, 0,  1,  2,  3,  4,
        5,  6,  7,  8,  9,  10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, -1, -1, -1, -1, -1, -1,
        26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51};

    auto decoded_size = [&in]() -> usize
    {
        const usize len = in.size();
        usize ret       = len / 4 * 3;
        for ( usize i = len; (i--) > 0; )
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
    };

    auto is_valid_char = [](unsigned char c) -> bool
    {
        return ((std::isalnum(c) != 0) || (c == '+') || (c == '/') || (c == '='));
    };

    const usize len    = in.size();
    const usize outlen = decoded_size();

    if ( !len || !outlen )
        return Err(ErrorCode::InvalidParameter);

    if ( len % 4 != 0 )
        return Err(ErrorCode::ArithmeticError);

    for ( usize i = 0; i < len; i++ )
    {
        if ( is_valid_char(in.at(i)) == false )
        {
            return Err(ErrorCode::IllegalValue);
        }
    }

    std::vector<u8> out(outlen, 0);
    for ( usize i = 0, j = 0; i < len; i += 4, j += 3 )
    {
        int v = b64_inverted_table.at(in.at(i) - 43);
        v     = (v << 6) | b64_inverted_table.at(in.at(i + 1) - 43);
        v     = in[i + 2] == '=' ? v << 6 : (v << 6) | b64_inverted_table.at(in.at(i + 2) - 43);
        v     = in[i + 3] == '=' ? v << 6 : (v << 6) | b64_inverted_table.at(in.at(i + 3) - 43);

        out[j] = (v >> 16) & 0xFF;
        if ( in[i + 2] != '=' )
            out[j + 1] = (v >> 8) & 0xFF;
        if ( in[i + 3] != '=' )
            out[j + 2] = v & 0xFF;
    }

    return Ok(out);
}


auto
to_string(_In_ std::wstring_view const& wstr) -> std::string
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
to_wstring(std::string_view const& str) noexcept -> std::wstring
{
    return to_widestring(str);
}


auto
to_widestring(std::string_view const& str) noexcept -> std::wstring
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
wstring_to_bytes(_In_ std::wstring_view const& str) -> std::vector<u8>
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
string_to_bytes(_In_ std::string_view const& str) -> std::vector<u8>
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
