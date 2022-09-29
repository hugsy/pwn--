#pragma once

#include <concepts>
#include <optional>
#include <type_traits>
#include <variant>

#include "common.hpp"


using flattenable_t = std::variant<std::string, std::wstring, std::vector<u8>>;

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
    Encode(const u8* buffer, const size_t buffer_length) -> Result<std::string>;


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


///
/// @brief Convert a `std::string` to `std::wstring`
///
/// @param str the string to convert
/// @return std::wstring
///
PWNAPI auto
to_widestring(const std::string_view& str) noexcept -> std::wstring;


///
/// @brief Alias for `pwn::utils::to_widestring`
///
/// @param str the string to convert
/// @return std::wstring
///
PWNAPI auto
to_wstring(const std::string_view& str) noexcept -> std::wstring;


///
/// @brief
///
PWNAPI auto
to_string(const std::wstring_view& ws) -> std::string;


///
/// @brief
///
PWNAPI auto
wstring_to_bytes(_In_ const std::wstring_view& str) -> std::vector<u8>;


///
/// @brief
///
PWNAPI auto
string_to_bytes(_In_ std::string_view const& str) -> std::vector<u8>;

///
/// @brief
///
PWNAPI auto
to_wstring(std::string_view const& str) noexcept -> std::wstring;

///
/// @brief
///
PWNAPI auto
to_widestring(std::string_view const& str) noexcept -> std::wstring;

///
/// @brief
///
PWNAPI auto
split(_In_ const std::wstring& ws, _In_ wchar_t delim) -> std::vector<std::wstring>;

///
/// @brief
///
PWNAPI auto
join(_In_ const std::vector<std::wstring>& args) -> std::wstring;

///
/// @brief
///
PWNAPI auto
strip(_In_ std::wstring const& args) -> std::wstring;

///
/// @brief
///
PWNAPI auto
strip(_In_ std::string const& args) -> std::string;


///
/// @brief
///
PWNAPI auto
startswith(_In_ const std::string& str, _In_ const std::string& pattern) -> bool;

///
/// @brief
///
PWNAPI auto
startswith(_In_ const std::wstring& str, _In_ const std::wstring& pattern) -> bool;

///
/// @brief
///
PWNAPI auto
endswith(_In_ const std::string& str, _In_ const std::string& pattern) -> bool;

///
/// @brief
///
PWNAPI auto
endswith(_In_ const std::wstring& str, _In_ const std::wstring& pattern) -> bool;


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
/// @brief
///
/// @param dwSize
/// @param dwPeriod
/// @param buffer
/// @return true
/// @return false
///
PWNAPI auto
cyclic(_In_ u32 dwSize, _In_ u32 dwPeriod, _Out_ std::vector<u8>& buffer) -> bool;

///
/// @brief
///
PWNAPI auto
cyclic(_In_ u32 dwSize, _In_ u32 dwPeriod) -> std::vector<u8>;

///
/// @brief
///
PWNAPI auto
cyclic(_In_ u32 dwSize, _Out_ std::vector<u8>& buffer) -> bool;

///
/// @brief
///
PWNAPI auto
cyclic(_In_ u32 dwSize) -> std::vector<u8>;


///
/// @brief Prints a hexdump of the given buffer and size
///
/// @param Buffer
/// @param BufferSize
///
PWNAPI void
hexdump(const u8* Buffer, const size_t BufferSize);


///
/// @brief
///
PWNAPI void
hexdump(const std::vector<u8>& bytes);

///
/// @brief
///
/// @param sleep_duration
/// @return void<class Rep, class Period>
///
template<class Rep, class Period>
void PWNAPI
sleep(const std::chrono::duration<Rep, Period>& sleep_duration);


///
/// @brief Pause the execution
///
void PWNAPI
pause();


///
/// @brief Breakpoint the execution
///
void PWNAPI
debugbreak();

} // namespace pwn::utils
