#pragma once

#include <optional>
#include <type_traits>
#include <variant>

#include "common.hpp"
#include "context.hpp"


#define PWN_UTILS_LOWER_CHARSET "abcdefghijklmnopqrstuvwxyz"
#define PWN_UTILS_UPPER_CHARSET "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
#define PWN_UTILS_DIGITS_CHARSET "0123456789"
#define PWN_UTILS_UPPER_LOWER_CHARSET PWN_UTILS_LOWER_CHARSET PWN_UTILS_UPPER_CHARSET
#define PWN_UTILS_ALNUM_CHARSET PWN_UTILS_UPPER_LOWER_CHARSET PWN_UTILS_DIGITS_CHARSET
#define PWN_UTILS_PRINTABLE_CHARSET PWN_UTILS_ALNUM_CHARSET "!\"#$ % &'()*+,-./:;<=>?@[\\]^_`{|}~ "


using flattenable_t = std::variant<std::string, std::wstring, std::vector<u8>>;

namespace pwn::utils
{
namespace random
{
PWNAPI void
seed();
PWNAPI auto
rand() -> u64;
PWNAPI auto
rand(_In_ u32 min, _In_ u32 max) -> u64;
PWNAPI auto
byte() -> u8;
PWNAPI auto
word() -> u16;
PWNAPI auto
dword() -> u32;
PWNAPI auto
qword() -> u64;
PWNAPI auto
string(_In_ u32 length) -> std::wstring;
PWNAPI auto
alnum(_In_ u32 length) -> std::wstring;
PWNAPI auto
buffer(_In_ u32 length) -> std::vector<u8>;
} // namespace random

PWNAPI auto
base64_encode(_In_ const u8* bytes_to_encode, _In_ size_t in_len) -> std::string;
PWNAPI auto
base64_encode(_In_ std::vector<u8> const& bytes) -> std::string;
PWNAPI auto
base64_decode(_In_ std::string const& encoded_string) -> std::optional<std::vector<u8>>;

PWNAPI auto
to_widestring(_In_ const std::string& s) -> std::wstring;
PWNAPI auto
to_string(_In_ const std::wstring& ws) -> std::string;
PWNAPI auto
wstring_to_bytes(_In_ const std::wstring& str) -> std::vector<u8>;
PWNAPI auto
string_to_bytes(_In_ std::string const& str) -> std::vector<u8>;
PWNAPI auto
to_widestring(_In_ std::string const& str) -> std::wstring;
PWNAPI auto
split(_In_ const std::wstring& ws, _In_ wchar_t delim) -> std::vector<std::wstring>;
PWNAPI auto
join(_In_ const std::vector<std::wstring>& args) -> std::wstring;
PWNAPI auto
strip(_In_ std::wstring const& args) -> std::wstring;
PWNAPI auto
strip(_In_ std::string const& args) -> std::string;

namespace path
{
PWNAPI auto
abspath(_In_ const std::wstring& path) -> std::wstring;
}

PWNAPI auto
startswith(_In_ const std::string& str, _In_ const std::string& pattern) -> bool;
PWNAPI auto
startswith(_In_ const std::wstring& str, _In_ const std::wstring& pattern) -> bool;
PWNAPI auto
endswith(_In_ const std::string& str, _In_ const std::string& pattern) -> bool;
PWNAPI auto
endswith(_In_ const std::wstring& str, _In_ const std::wstring& pattern) -> bool;

PWNAPI auto
p8(_In_ u8 v) -> std::vector<u8>;
PWNAPI auto
p16(_In_ u16 v) -> std::vector<u8>;
PWNAPI auto
p32(_In_ u32 v) -> std::vector<u8>;
PWNAPI auto
p64(_In_ u64 v) -> std::vector<u8>;

PWNAPI auto
flatten(_In_ const std::vector<flattenable_t>& args) -> std::vector<u8>;

PWNAPI auto
cyclic(_In_ u32 dwSize, _In_ u32 dwPeriod, _Out_ std::vector<u8>& buffer) -> bool;
PWNAPI auto
cyclic(_In_ u32 dwSize, _In_ u32 dwPeriod) -> std::vector<u8>;
PWNAPI auto
cyclic(_In_ u32 dwSize, _Out_ std::vector<u8>& buffer) -> bool;
PWNAPI auto
cyclic(_In_ u32 dwSize) -> std::vector<u8>;

PWNAPI void
hexdump(_In_ const u8* Buffer, _In_ size_t BufferSize);
PWNAPI void
hexdump(_In_ const std::vector<u8>& bytes);


///
/// @brief Pause the execution
///
void PWNAPI
pause();


///
/// @brief Breakpoint the execution
///
void
debugbreak();

} // namespace pwn::utils
