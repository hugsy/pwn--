#pragma once

#include "common.h"


#define MD5LEN  16
#define SHA1LEN  20
#define SHA256LEN  32
#define SHA512LEN  64


namespace pwn::crypto
{
	/**
	 * CRCx
	 */
	PWNAPI auto crc8(std::vector<BYTE> const&) -> BYTE;
	PWNAPI auto crc16(std::vector<BYTE> const&) -> WORD;
	PWNAPI auto crc32(std::vector<BYTE> const&) -> DWORD;
	PWNAPI auto crc64(std::vector<BYTE> const&) -> DWORD64;


	/**
	 * MDx
	 */

	PWNAPI auto md2(std::vector<BYTE> const& data) -> std::array<BYTE, MD5LEN>;
	PWNAPI auto md4(std::vector<BYTE> const& data) -> std::array<BYTE, MD5LEN>;
	PWNAPI auto md5(std::vector<BYTE> const& data) -> std::array<BYTE, MD5LEN>;



	/**
	 * SHAx
	 */
	PWNAPI auto sha1(std::vector<BYTE> const& data) -> std::array<BYTE, SHA1LEN>;
	PWNAPI auto sha256(std::vector<BYTE> const& data) -> std::array<BYTE, SHA256LEN>;
	PWNAPI auto sha512(std::vector<BYTE> const& data) -> std::array<BYTE, SHA512LEN>;
}