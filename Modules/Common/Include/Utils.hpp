#pragma once

#include <algorithm>
#include <concepts>
#include <filesystem>
#include <optional>
#include <span>
#include <thread>
#include <type_traits>
#include <unordered_map>
#include <variant>

#include "Architecture.hpp"
#include "Common.hpp"


namespace pwn::Utils
{

using MemoryView = std::span<u8*>;

namespace StringLib
{

namespace Charset
{
constexpr std::string_view Lower        = "abcdefghijklmnopqrstuvwxyz";
constexpr std::string_view Upper        = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
constexpr std::string_view UpperLower   = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
constexpr std::string_view Digits       = "0123456789";
constexpr std::string_view Alphanumeric = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
constexpr std::string_view AllPrintable =
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!\"#$ % &'()*+,-./:;<=>?@[\\]^_`{|}~ ";
constexpr std::string_view Basic64Characters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789/+";

constexpr std::wstring_view WideLower        = L"abcdefghijklmnopqrstuvwxyz";
constexpr std::wstring_view WideUpper        = L"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
constexpr std::wstring_view WideUpperLower   = L"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
constexpr std::wstring_view WideDigits       = L"0123456789";
constexpr std::wstring_view WideAlphanumeric = L"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
constexpr std::wstring_view WideAllPrintable =
    L"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!\"#$ % &'()*+,-./:;<=>?@[\\]^_`{|}~ ";
} // namespace Charset

///
///@brief Inefficient but generic templated string conversion function
///
///@tparam ToType
///@tparam FromType
///@tparam T
///@param src
///@return ToType
///
template<typename ToType, typename FromType, typename T = char>
static ToType
To(FromType const& src)
{
    ToType dst;
    std::transform(
        src.cbegin(),
        src.cend(),
        std::back_inserter(dst),
        [](auto const c)
        {
            return static_cast<T>(c);
        });
    return dst;
}

static std::string
To(std::wstring const& src);

template<typename T, typename L>
static std::vector<T>
Split(T const& src, const L delim)
{
    T cur;
    std::vector<T> dst;
    std::for_each(
        src.cbegin(),
        src.cend(),
        [&dst, &cur, &delim](const L& x)
        {
            if ( x == delim )
            {
                dst.push_back(cur);
                cur.clear();
            }
            else
            {
                cur += x;
            }
        });
    if ( !cur.empty() )
    {
        dst.push_back(cur);
    }
    return dst;
}

///
/// @brief
///
template<typename T, typename L>
static T
Join(const std::vector<T>& Src, const L delim)
{
    T Dst;
    std::for_each(
        Src.cbegin(),
        Src.cend() - 1,
        [&Dst, &delim](const T& x)
        {
            Dst += x + T {delim};
        });
    Dst += Src.back();
    return Dst;
}

///
/// @brief
///
template<typename T, typename L>
static T
Strip(T const& Src, const L c)
{
    T Dst {Src};
    std::erase_if(
        Dst,
        [&c](auto const& x)
        {
            return x == c;
        });
    return Dst;
}
}; // namespace StringLib


namespace Random
{
///
/// @brief (Re-)Seed the internal PRNG
///
void
Seed(std::optional<u64> seed = std::nullopt);


///
/// @brief Get the next pseudo random number.
///
/// @return a pseudo random number
///
auto
Next() -> u64;


///
/// @brief Same as `rand()` but within an interval
///
/// @param max a u64 value, the maximum interval value
/// @param min a u64 value, the minimum interval value. If not provided, `0`
/// @return u64
///
auto
Next(u64 const max, u64 const min) noexcept -> u64;


///
///@brief Returns a random BYTE
///
///@return u8
///
auto
Byte() -> u8;


///
///@brief Returns a random WORD
///
///@return u16
///
auto
Word() -> u16;


///
///@brief Returns a random DWORD
///
///@return u32
///
auto
Dword() -> u32;


///
///@brief Returns a random QWORD
///
///@return u64
///
auto
Qword() -> u64;


///
///@brief
///
///@param length
///@param charset
///@return std::string
///
auto
String(u32 length, std::string_view const& charset = Utils::StringLib::Charset::AllPrintable) -> std::string;


///
/// @brief
///
auto
WideString(u32 length, std::wstring_view const& charset = Utils::StringLib::Charset::WideAllPrintable) -> std::wstring;


///
/// @brief
///
auto
AlnumWideString(u32 length) -> std::wstring;


///
/// @brief
///
auto
Buffer(u32 length) -> std::vector<u8>;
} // namespace Random


///
///@brief
///
///
class Base64
{
public:
    ///
    /// @brief Encode a buffer of a given size to base64
    ///
    /// @param buffer the buffer to encode
    /// @param buffer_length the buffer expected size
    /// @return Result<std::string> a b64 string on success, Err() type otherwise
    ///
    static auto
    Encode(const u8* buffer, const usize buffer_length) -> Result<std::string>;


    ///
    /// @brief Encode a vector of bytes to base64
    ///
    /// @param bytes the vector to encode
    /// @return Result<std::string> a b64 string on success, Err() type otherwise
    ///
    static auto
    Encode(std::vector<u8> const& bytes) -> Result<std::string>;


    ///
    /// @brief Decode a base64 string
    ///
    /// @param encoded_string
    /// @return Result<std::vector<u8>> a vector of bytes on success, Err() type otherwise
    ///
    static auto
    Decode(std::string_view const& encoded_string) -> Result<std::vector<u8>>;
};


class Pack
{
public:
    ///
    ///@brief Pack a 8-byte to a byte vector
    ///
    ///@param v the value to pack
    ///@param e the endianess (default: used from `Context`)
    ///@return std::vector<u8>
    ///
    static std::vector<u8>
    p64(u64 v, Endianess e = Endianess::unknown);


    ///
    ///@brief Pack a 3-byte to a byte vector
    ///
    ///@param v the value to pack
    ///@param e the endianess (default: used from `Context`)
    ///@return std::vector<u8>
    ///
    static std::vector<u8>
    p32(u32 v, Endianess e = Endianess::unknown);


    ///
    ///@brief Pack a 2-byte to a byte vector
    ///
    ///@param v the value to pack
    ///@param e the endianess (default: used from `Context`)
    ///@return std::vector<u8>
    ///
    static std::vector<u8>
    p16(u16 v, Endianess e = Endianess::unknown);


    ///
    ///@brief Pack a 1-byte to a byte vector
    ///
    ///@param v the value to pack
    ///@param e the endianess (default: used from `Context`)
    ///@return std::vector<u8>
    ///
    static std::vector<u8>
    p8(u8 v, Endianess e = Endianess::unknown);


    ///
    ///@brief P
    ///
    ///@tparam T
    ///@tparam Args
    ///@param arg
    ///@param args
    ///@return constexpr std::vector<u8>
    ///
    template<Flattenable T, Flattenable... Args>
    static std::vector<u8>
    Flatten(T arg, Args... args)
    {
        std::vector<u8> out;

        if constexpr ( std::is_same_v<T, std::string> )
        {
            std::vector<u8> s = StringLib::To<std::vector<u8>>(std::string(arg));
            out.insert(out.end(), s.begin(), s.end());
        }

        if constexpr ( std::is_same_v<T, std::wstring> )
        {
            std::vector<u8> s = StringLib::To<std::vector<u8>>(std::wstring(arg));
            out.insert(out.end(), s.begin(), s.end());
        }

        if constexpr ( std::is_same_v<T, std::vector<u8>> )
        {
            out.insert(out.end(), arg.begin(), arg.end());
        }

        if constexpr ( sizeof...(args) > 0 )
        {
            auto rec = Flatten(args...);
            out.insert(out.end(), rec.begin(), rec.end());
        }

        return out;
    }
};


///
///@brief Upper align address to the given size
///
///@param a
///@param sz
///@return PWNAPI
///
PWNAPI uptr
align(uptr a, u32 sz);


///
/// @brief Generate a de-Bruijn sequence
///
/// @param dwSize
/// @param dwPeriod
/// @return false
///
PWNAPI auto
cyclic(u32 Size, u32 Period = 0) -> Result<std::vector<u8>>;


///
/// @brief Prints a hexdump of the given buffer and size
///
/// @param Buffer
/// @param BufferSize
///
PWNAPI void
Hexdump(const u8* Buffer, const usize BufferSize);


///
/// @brief
///
PWNAPI void
Hexdump(std::vector<u8> const& bytes);


///
/// @brief
///
PWNAPI void
Hexdump(Utils::MemoryView const& view);


///
/// @brief
///
/// @param sleep_duration
/// @return void<class Rep, class Period>
///
template<class Rep, class Period>
void
Sleep(const std::chrono::duration<Rep, Period>& sleep_duration)
{
    std::this_thread::sleep_for(sleep_duration);
}


///
/// @brief Pause the execution
///
void PWNAPI
Pause();


///
/// @brief Breakpoint the execution
///
void PWNAPI
DebugBreak();


///
///@brief Get the security characteristics of an executable. Ported from
/// https://github.com/hugsy/stuff/blob/main/CheckSec.c#L131
///
///@param FilePath
///@return Result<std::unordered_map<u16, bool>>
///
/// TODO move this to Binary/PE
///
Result<std::unordered_map<u16, bool>>
GetExecutableCharacteristics(std::filesystem::path const& FilePath);


///
///@brief Get the executable signature information. Ported from
/// https://github.com/hugsy/stuff/blob/main/CheckSec.c#L66
///
///@param FilePath
///@return Result<bool>
///
///
/// TODO move this to Binary/PE
///
Result<bool>
GetExecutableSignature(std::filesystem::path const& FilePath);

} // namespace pwn::Utils
