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
	PWNAPI BYTE crc8(std::vector<BYTE> const&);
	PWNAPI WORD crc16(std::vector<BYTE> const&);
	PWNAPI DWORD crc32(std::vector<BYTE> const&);
	PWNAPI DWORD64 crc64(std::vector<BYTE> const&);


	/**
	 * MDx
	 */

	PWNAPI std::array<BYTE, MD5LEN> md2(std::vector<BYTE> const& data);
	PWNAPI std::array<BYTE, MD5LEN> md4(std::vector<BYTE> const& data);
	PWNAPI std::array<BYTE, MD5LEN> md5(std::vector<BYTE> const& data);



	/**
	 * SHAx
	 */
	PWNAPI std::array<BYTE, SHA1LEN> sha1(std::vector<BYTE> const& data);
	PWNAPI std::array<BYTE, SHA256LEN> sha256(std::vector<BYTE> const& data);
	PWNAPI std::array<BYTE, SHA512LEN> sha512(std::vector<BYTE> const& data);
}