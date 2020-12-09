#include "crypto.h"


#include <WinCrypt.h>


/**
* 
* Terrible CRC function implemention, just packaged here for convienence. Don't use for real code, use Boost.
* 
* https://en.wikipedia.org/wiki/Cyclic_redundancy_check
* 
*/


template <typename T>
static T __crc_base(std::vector<BYTE> const& data, T variant)
{
	auto n = data.size();
	T crc = -1;

	for (size_t i = 0; i < n; i++)
	{
		auto c = data.at(i);
		T b = (T)c;

		for (u8 j = 0; j < 8; j++)
		{
			b = (b ^ crc) & 1;
			crc >>= 1;
			if (b)
				crc = crc ^ variant;
			b >>= 1;
		}
	}
	return ~crc;
}



BYTE pwn::crypto::crc8(std::vector<BYTE> const& data)
{
	return __crc_base<BYTE>(data, (BYTE)Crc8Variant::Crc8Bluetooth);
}


WORD pwn::crypto::crc16(std::vector<BYTE> const& data)
{
	return __crc_base<WORD>(data, (WORD)Crc16Variant::Crc16Ccitt);
}


DWORD pwn::crypto::crc32(std::vector<BYTE> const& data)
{
	return __crc_base<DWORD>(data, (DWORD)Crc32Variant::Crc32);
}


DWORD64 pwn::crypto::crc64(std::vector<BYTE> const& data)
{
	return __crc_base<DWORD64>(data, (DWORD64)Crc64Variant::Crc64Ecma);
}


// todo: implem sha1, sha256, sha512 with cryptoapi 

std::array<BYTE, MD5LEN> __calc_hash_md(std::vector<BYTE> const& data, DWORD dwMdType)
{
	std::array<BYTE, MD5LEN> out = {};
	auto n = data.size();
	HCRYPTPROV hProv = 0;
	HCRYPTHASH hHash = 0;
	DWORD cbHash = MD5LEN;

	CryptAcquireContext(&hProv, nullptr, nullptr, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT);
	CryptCreateHash(hProv, dwMdType, 0, 0, &hHash);
	CryptHashData(hHash, data.data(), n, 0);
	CryptGetHashParam(hHash, HP_HASHVAL, &out[0], &cbHash, 0);
	CryptDestroyHash(hHash);
	CryptReleaseContext(hProv, 0);
	return out;
}

std::array<BYTE, MD5LEN> pwn::crypto::md2(std::vector<BYTE> const& data) {	return __calc_hash_md(data, CALG_MD2); }
std::array<BYTE, MD5LEN> pwn::crypto::md4(std::vector<BYTE> const& data) {	return __calc_hash_md(data, CALG_MD4); }
std::array<BYTE, MD5LEN> pwn::crypto::md5(std::vector<BYTE> const& data) {	return __calc_hash_md(data, CALG_MD5); }