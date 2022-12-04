#pragma once

#include <concepts>
#include <filesystem>
#include <optional>
#include <type_traits>
#include <unordered_map>
#include <variant>

#include "common.hpp"


///
/// @brief Same as Python's `all`
///
/// @tparam Args an `std::integral` templating type
/// @param args the variadic parameters to check
/// @return true if all variadic parameters are true
/// @return false otherwise
///
template<std::integral... Args>
bool
all(Args... args);


///
/// @brief Same as Python's `any`
///
/// @tparam Args an `std::integral` templating type
/// @param args the variadic parameters to check
/// @return true if any variadic parameter is true
/// @return false otherwise
///
template<std::integral... Args>
bool
any(Args... args);


///
/// @brief Opposite of `all`
///
/// @tparam Args an `std::integral` templating type
/// @param args the variadic parameters to check
/// @return true if all variadic parameters are false
/// @return false otherwise
///
template<std::integral... Args>
bool
none(Args... args);


namespace pwn::utils
{
namespace random
{
///
/// @brief (Re-)Seed the internal PRNG
///
PWNAPI void
seed(std::optional<u64> seed = std::nullopt);


///
/// @brief Get the next pseudo random number.
///
/// @return a pseudo random number
///
PWNAPI auto
rand() -> u64;


///
/// @brief Same as `rand()` but within an interval
///
/// @param max a u64 value, the maximum interval value
/// @param min a u64 value, the minimum interval value. If not provided, `0`
/// @return u64
///
PWNAPI auto
rand(u64 const max, u64 const min) noexcept -> u64;


///
/// @brief
///
PWNAPI auto
byte() -> u8;


///
/// @brief
///
PWNAPI auto
word() -> u16;


///
/// @brief
///
PWNAPI auto
dword() -> u32;


///
/// @brief
///
PWNAPI auto
qword() -> u64;


///
/// @brief
///
PWNAPI auto
string(_In_ u32 length) -> std::wstring;


///
/// @brief
///
PWNAPI auto
alnum(_In_ u32 length) -> std::wstring;


///
/// @brief
///
PWNAPI auto
buffer(_In_ u32 length) -> std::vector<u8>;
} // namespace random


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


class StringLib
{
public:
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
};


///
/// @brief
///
PWNAPI auto
p8(_In_ u8 v) -> std::vector<u8>;


///
/// @brief
///
PWNAPI auto
p16(_In_ u16 v) -> std::vector<u8>;


///
/// @brief
///
PWNAPI auto
p32(_In_ u32 v) -> std::vector<u8>;


///
/// @brief
///
PWNAPI auto
p64(_In_ u64 v) -> std::vector<u8>;


///
/// @brief
///
/// @param args
/// @return std::vector<u8>
///
PWNAPI auto
flatten(const std::vector<flattenable_t>& args) -> std::vector<u8>;

///
///@brief
///
///@param a
///@param sz
///@return PWNAPI
///
PWNAPI uptr
align(uptr a, usize sz);

///
/// @brief
///
/// @param dwSize
/// @param dwPeriod
/// @return false
///
PWNAPI auto
cyclic(_In_ u32 Size, _In_ u32 Period = 0) -> Result<std::vector<u8>>;


///
/// @brief Prints a hexdump of the given buffer and size
///
/// @param Buffer
/// @param BufferSize
///
PWNAPI void
hexdump(const u8* Buffer, const usize BufferSize);


///
/// @brief
///
PWNAPI void
hexdump(std::vector<u8> const& bytes);


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
Result<std::unordered_map<u16, bool>>
GetExecutableCharacteristics(std::filesystem::path const& FilePath);


///
///@brief Get the executable signature information. Ported from
/// https://github.com/hugsy/stuff/blob/main/CheckSec.c#L66
///
///@param FilePath
///@return Result<bool>
///
Result<bool>
GetExecutableSignature(std::filesystem::path const& FilePath);

} // namespace pwn::utils
