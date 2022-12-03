#include "utils.hpp"

#include <algorithm>
#include <cstdio>
#include <ctime>
#include <iomanip>
#include <iostream>
#include <ranges>
#include <sstream>
#include <thread>
#include <type_traits>

#include "handle.hpp"
#include "log.hpp"
#include "pwn.hpp"

extern struct pwn::GlobalContext pwn::Context;

// clang-format off
#define PWN_UTILS_LOWER_CHARSET           "abcdefghijklmnopqrstuvwxyz"
#define PWN_UTILS_UPPER_CHARSET           "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
#define PWN_UTILS_DIGITS_CHARSET          "0123456789"
#define PWN_UTILS_UPPER_LOWER_CHARSET     PWN_UTILS_LOWER_CHARSET PWN_UTILS_UPPER_CHARSET
#define PWN_UTILS_ALNUM_CHARSET           PWN_UTILS_UPPER_LOWER_CHARSET PWN_UTILS_DIGITS_CHARSET
#define PWN_UTILS_PRINTABLE_CHARSET       PWN_UTILS_ALNUM_CHARSET "!\"#$ % &'()*+,-./:;<=>?@[\\]^_`{|}~ "
// clang-format on

namespace fs = std::filesystem;

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


///
/// better rand() using xorshift, stolen from gamozo
///
auto
xorshift64() -> u64
{
    auto seed = pwn::Context.m_seed;
    seed ^= seed << 13;
    seed ^= seed >> 17;
    seed ^= seed << 43;
    pwn::Context.m_seed = seed;
    return seed;
}


///
///@brief C version of the algorithm implemented in GEF
///
///@param t
///@param p
///@param dwSize
///@param Alphabet
///@param period
///@param aIndex
///@param lpResult
///
void
create_cyclic_buffer(
    const u32 t,
    const u32 p,
    const usize DesiredBufferSize,
    const std::string_view& Alphabet,
    const u32 Period,
    u32* aIndex,
    std::vector<u8>& Result)
{

    if ( Result.size() == DesiredBufferSize )
    {
        return;
    }

    if ( t > Period )
    {
        if ( (Period % p) == 0 )
        {
            for ( u32 j = 1; j < p + 1; j++ )
            {
                Result.push_back(Alphabet[aIndex[j]]);
                if ( Result.size() == DesiredBufferSize )
                {
                    return;
                }
            }
        }
    }
    else
    {
        aIndex[t] = aIndex[t - p];
        create_cyclic_buffer(t + 1, p, DesiredBufferSize, Alphabet, Period, aIndex, Result);
        for ( u32 j = aIndex[t - p] + 1; j < Alphabet.size(); j++ )
        {
            aIndex[t] = j;
            create_cyclic_buffer(t + 1, t, DesiredBufferSize, Alphabet, Period, aIndex, Result);
        }
    }

    return;
}

} // namespace


void
random::seed(std::optional<u64> seed)
{
    dbg(L"Re-seeding globals");

    if ( seed )
    {
        pwn::Context.m_seed = seed.value();
    }
    else
    {
        pwn::Context.m_seed = time(nullptr);
    }

    std::srand(pwn::Context.m_seed);
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
    buffer.resize(length);
    std::for_each(
        buffer.begin(),
        buffer.end(),
        [](u8& x)
        {
            x = random::byte();
        });
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
        std::lock_guard<std::mutex> guard(pwn::Context.m_ConsoleMutex);
        std::wcout << hexstr.str();
    }
}


void
hexdump(const std::vector<u8>& bytes)
{
    hexdump((const u8*)bytes.data(), (usize)bytes.size());
}


auto
Base64::Encode(std::vector<u8> const& bytes) -> Result<std::string>
{
    return Base64::Encode(bytes.data(), bytes.size());
}


auto
Base64::Encode(const u8* in, const usize len) -> Result<std::string>
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
Base64::Decode(std::string_view const& in) -> Result<std::vector<u8>>
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

uptr
align(uptr a, usize sz)
{
    return (a + sz - 1) & (~(sz - 1));
}


Result<std::vector<u8>>
cyclic(_In_ u32 Size, _In_ u32 Period)
{
    std::vector<u8> Buffer;
    const std::string_view Alphabet = "abcdefghijklmnopqrstuvwxyz";
    Buffer.clear();
    u32 _Period = Period ? Period : pwn::Context.ptrsize;
    auto aIndex = std::make_unique<u32[]>(Alphabet.size() * _Period);
    create_cyclic_buffer(1, 1, Size, Alphabet, _Period, aIndex.get(), Buffer);
    return Ok(Buffer);
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
    if ( pwn::Context.endianess == Endianess::little )
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
        return StringLib::To<std::vector<u8>>(s);
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
Pause()
{
    dbg("Pausing, press enter to resume...");
    std::cin.get();
}


void
DebugBreak()
{
    dbg("Breakpointing...");
    ::DebugBreak();
}


Result<std::unordered_map<u16, bool>>
GetExecutableCharacteristics(fs::path const& FilePath)
{
    std::unordered_map<u16, bool> SecProps {
        {IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA, false},
        {IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE, false},
        {IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY, false},
        {IMAGE_DLLCHARACTERISTICS_NX_COMPAT, false},
        {IMAGE_DLLCHARACTERISTICS_NO_ISOLATION, false},
        {IMAGE_DLLCHARACTERISTICS_NO_SEH, false},
        {IMAGE_DLLCHARACTERISTICS_NO_BIND, false},
        {IMAGE_DLLCHARACTERISTICS_APPCONTAINER, false},
        {IMAGE_DLLCHARACTERISTICS_WDM_DRIVER, false},
        {IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE, false},
#ifdef IMAGE_DLLCHARACTERISTICS_EX_CET_COMPAT
        {IMAGE_DLLCHARACTERISTICS_EX_CET_COMPAT, false},
#endif // IMAGE_DLLCHARACTERISTICS_EX_CET_COMPAT
    };

    auto hFile = pwn::UniqueHandle {::CreateFileW(
        FilePath.c_str(),
        GENERIC_READ,
        FILE_SHARE_READ,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr)};
    if ( !hFile )
    {
        return Err(ErrorCode::ExternalApiCallFailed);
    }

    const u32 FileSize = ::GetFileSize(hFile.get(), nullptr);

    auto hFileMap = pwn::UniqueHandle {::CreateFileMappingW(hFile.get(), nullptr, PAGE_READONLY, 0, 0, nullptr)};
    if ( !hFileMap )
    {
        return Err(ErrorCode::ExternalApiCallFailed);
    }

    uptr pMappedData = (uptr)::MapViewOfFile(hFileMap.get(), FILE_MAP_READ, 0, 0, 0);

    const IMAGE_DOS_HEADER* pDosHeader = reinterpret_cast<IMAGE_DOS_HEADER*>(pMappedData);

    if ( pDosHeader->e_magic != IMAGE_DOS_SIGNATURE )
    {
        return Err(ErrorCode::BadSignature);
    }

    if ( pDosHeader->e_lfanew >= FileSize )
    {
        return Err(ErrorCode::ParsingError);
    }


    const IMAGE_NT_HEADERS* pPeHeader = reinterpret_cast<IMAGE_NT_HEADERS*>(pMappedData + pDosHeader->e_lfanew);

    if ( pPeHeader->Signature != IMAGE_NT_SIGNATURE )
    {
        return Err(ErrorCode::ParsingError);
    }

    IMAGE_OPTIONAL_HEADER const& pOptionalHeader = pPeHeader->OptionalHeader;

    for ( auto Flag : std::views::keys(SecProps) )
    {
        SecProps[Flag] = (pOptionalHeader.DllCharacteristics & Flag) != 0;
    }

    return Ok(SecProps);
}

Result<bool>
GetExecutableSignature(fs::path const& FilePath)
{
    return Ok(true);
}

} // namespace pwn::utils
