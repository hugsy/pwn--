#pragma once

#include "common.h"


#define MD5LEN  16


namespace pwn::crypto
{
	/**
	 * CRC 
	 */
	enum class Crc8Variant : BYTE
	{
		Crc8Bluetooth = 0xE5,
	};

	enum class Crc16Variant : WORD
	{
		Crc16Ccitt = 0x8408,
	};

	enum class Crc32Variant : DWORD
	{
		Crc32 = 0xEDB88320,
		Crc32Castagnoli = 0x82F63B78,
		Crc32Koopman = 0xEB31D82E,
		Crc32Koopman2 = 0x992C1A4C
	};

	enum class Crc64Variant : DWORD64
	{
		Crc64Iso = 0xD800000000000000,
		Crc64Ecma = 0xC96C5795D7870F42
	};

	PWNAPI BYTE crc8(std::vector<BYTE> const&);
	PWNAPI WORD crc16(std::vector<BYTE> const&);
	PWNAPI DWORD crc32(std::vector<BYTE> const&);
	PWNAPI DWORD64 crc64(std::vector<BYTE> const&);


	/**
	 * MD
	 */

	PWNAPI std::array<BYTE, MD5LEN> md2(std::vector<BYTE> const& data);
	PWNAPI std::array<BYTE, MD5LEN> md4(std::vector<BYTE> const& data);
	PWNAPI std::array<BYTE, MD5LEN> md5(std::vector<BYTE> const& data);



	/**
	 * SHA
	 */
}