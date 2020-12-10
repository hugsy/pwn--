#include "crypto.h"


#include <WinCrypt.h>


/**
 * 
 * Those are NOT valid CRC implementations!! Use https://en.wikipedia.org/wiki/Cyclic_redundancy_check for that
 * I used those for fast hashing, not for redundancy check.
 * 
 */


template <typename T>
static T __crc_base(std::vector<BYTE> const& data, T variant)
{
	auto n = data.size();
	T crc = -1;
	for (auto i = 0; i < n; i++)
	{
		auto c = data.at(i);
		T b = (T)c;

		for (auto j = 0; j < 8; j++)
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
	return __crc_base<BYTE>(data, 0xE5);
}


WORD pwn::crypto::crc16(std::vector<BYTE> const& data)
{
	return __crc_base<WORD>(data, 0x8408);
}


DWORD pwn::crypto::crc32(std::vector<BYTE> const& data)
{
	return __crc_base<DWORD>(data, 0xEDB88320);
}


DWORD64 pwn::crypto::crc64(std::vector<BYTE> const& data)
{
	return __crc_base<DWORD64>(data, 0xC96C5795D7870F42);
}


// todo: implem sha1, sha256, sha512 with cryptoapi 
template <typename T>
static T __calc_hash(std::vector<BYTE> const& data, DWORD dwHashAlgVariant, DWORD dwProvider)
{
	T out = {};
	auto n = data.size();
	HCRYPTPROV hProv = 0;
	HCRYPTHASH hHash = 0;
	DWORD cbHash = out.size();


	if (CryptAcquireContext(&hProv, nullptr, nullptr, dwProvider, CRYPT_VERIFYCONTEXT))
	{
		if (CryptCreateHash(hProv, dwHashAlgVariant, 0, 0, &hHash))
		{
			if (CryptHashData(hHash, data.data(), n, 0))
			{
				CryptGetHashParam(hHash, HP_HASHVAL, &out[0], &cbHash, 0);
			}
			CryptDestroyHash(hHash);
		}
		CryptReleaseContext(hProv, 0);
	}
	return out;
}

std::array<BYTE, MD5LEN> pwn::crypto::md2(std::vector<BYTE> const& data) {return __calc_hash<std::array<BYTE, MD5LEN>>(data, CALG_MD2, PROV_RSA_FULL);}
std::array<BYTE, MD5LEN> pwn::crypto::md4(std::vector<BYTE> const& data) {return __calc_hash<std::array<BYTE, MD5LEN>>(data, CALG_MD4, PROV_RSA_FULL);}
std::array<BYTE, MD5LEN> pwn::crypto::md5(std::vector<BYTE> const& data) {return __calc_hash<std::array<BYTE, MD5LEN>>(data, CALG_MD5, PROV_RSA_FULL);}
std::array<BYTE, SHA1LEN> pwn::crypto::sha1(std::vector<BYTE> const& data) {return __calc_hash<std::array<BYTE, SHA1LEN>>(data, CALG_SHA1, PROV_RSA_FULL);}
std::array<BYTE, SHA256LEN> pwn::crypto::sha256(std::vector<BYTE> const& data) {return __calc_hash<std::array<BYTE, SHA256LEN>>(data, CALG_SHA_256, PROV_RSA_AES);}
std::array<BYTE, SHA512LEN> pwn::crypto::sha512(std::vector<BYTE> const& data) {return __calc_hash<std::array<BYTE, SHA512LEN>>(data, CALG_SHA_512, PROV_RSA_AES);}