#pragma once

#include "Common.hpp"


namespace pwn::Crypto
{

constexpr u32 MD5LEN    = 16;
constexpr u32 SHA1LEN   = 20;
constexpr u32 SHA256LEN = 32;
constexpr u32 SHA512LEN = 64;


PWNAPI auto
crc8(std::vector<u8> const&) -> u8;
PWNAPI auto
crc16(std::vector<u8> const&) -> u16;
PWNAPI auto
crc32(std::vector<u8> const&) -> u32;
PWNAPI auto
crc64(std::vector<u8> const&) -> u64;


#ifdef PWN_BUILD_FOR_WINDOWS
PWNAPI auto
md2(std::vector<u8> const& data) -> std::array<u8, MD5LEN>;
PWNAPI auto
md4(std::vector<u8> const& data) -> std::array<u8, MD5LEN>;
PWNAPI auto
md5(std::vector<u8> const& data) -> std::array<u8, MD5LEN>;


PWNAPI auto
sha1(std::vector<u8> const& data) -> std::array<u8, SHA1LEN>;
PWNAPI auto
sha256(std::vector<u8> const& data) -> std::array<u8, SHA256LEN>;
PWNAPI auto
sha512(std::vector<u8> const& data) -> std::array<u8, SHA512LEN>;
#endif
} // namespace Crypto
