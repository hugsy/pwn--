#pragma once

#include "Common.hpp"


namespace pwn::Crypto
{

//
// Constants
//

constexpr usize MD2LEN    = 16;
constexpr usize MD4LEN    = 16;
constexpr usize MD5LEN    = 16;
constexpr usize SHA1LEN   = 20;
constexpr usize SHA256LEN = 32;
constexpr usize SHA512LEN = 64;


PWNAPI auto
CRC8(std::vector<u8> const&) -> u8;

PWNAPI auto
CRC16(std::vector<u8> const&) -> u16;

PWNAPI auto
CRC32(std::vector<u8> const&) -> u32;

PWNAPI auto
CRC64(std::vector<u8> const&) -> u64;

PWNAPI auto
MD2(std::vector<u8> const& data) -> std::array<u8, MD2LEN>;

PWNAPI auto
MD4(std::vector<u8> const& data) -> std::array<u8, MD4LEN>;

PWNAPI auto
MD5(std::vector<u8> const& data) -> std::array<u8, MD5LEN>;

PWNAPI auto
SHA1(std::vector<u8> const& data) -> std::array<u8, SHA1LEN>;

PWNAPI auto
SHA256(std::vector<u8> const& data) -> std::array<u8, SHA256LEN>;

PWNAPI auto
SHA512(std::vector<u8> const& data) -> std::array<u8, SHA512LEN>;

} // namespace pwn::Crypto
