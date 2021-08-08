#include "crypto.hpp"

#if 0

#endif


#pragma region CRC
/**
 *
 * Those are NOT valid CRC implementations!! Use https://en.wikipedia.org/wiki/Cyclic_redundancy_check for that
 * I used those for fast hashing, not for redundancy check.
 *
 */

template<typename T>
static T
__crc_base(std::vector<u8> const& data, T variant)
{
    auto n = data.size();
    T crc  = -1;
    for ( size_t i = 0; i < n; i++ )
    {
        u8 c = data.at(i);
        T b  = (T)c;

        for ( auto j = 0; j < 8; j++ )
        {
            b = (b ^ crc) & 1;
            crc >>= 1;
            if ( b )
                crc = crc ^ variant;
            b >>= 1;
        }
    }
    return ~crc;
}

#define CRC8_VARIANT ((u8)0xE5)
#define CRC16_VARIANT ((u16)0x8408)
#define CRC32_VARIANT ((u32)0xEDB88320)
#define CRC64_VARIANT ((u64)0xC96C5795D7870F42)


u8
pwn::crypto::crc8(std::vector<u8> const& data)
{
    return __crc_base<u8>(data, CRC8_VARIANT);
}


u16
pwn::crypto::crc16(std::vector<u8> const& data)
{
    return __crc_base<u16>(data, CRC16_VARIANT);
}


u32
pwn::crypto::crc32(std::vector<u8> const& data)
{
    return __crc_base<u32>(data, CRC32_VARIANT);
}


u64
pwn::crypto::crc64(std::vector<u8> const& data)
{
    return __crc_base<u64>(data, CRC64_VARIANT);
}

#pragma endregion


//
// todo: make md/sha portable to linux too
//


#ifdef __PWNLIB_WINDOWS_BUILD__
#include <WinCrypt.h>

template <typename T>
static T __calc_hash(std::vector<u8> const& data, DWORD dwHashAlgVariant, DWORD dwProvider)
{
	T out = {};
	DWORD n = data.size() & 0xffffffff;
	HCRYPTPROV hProv = 0;
	HCRYPTHASH hHash = 0;
	DWORD cbHash = out.size() & 0xffffffff;

	if (CryptAcquireContext(&hProv, nullptr, nullptr, dwProvider, CRYPT_VERIFYCONTEXT))
	{
		if (::CryptCreateHash(hProv, dwHashAlgVariant, 0, 0, &hHash))
		{
			if (::CryptHashData(hHash, data.data(), n, 0))
			{
				::CryptGetHashParam(hHash, HP_HASHVAL, &out[0], &cbHash, 0);
			}
			::CryptDestroyHash(hHash);
		}
		::CryptReleaseContext(hProv, 0);
	}
	return out;
}

std::array<u8, MD5LEN> pwn::crypto::md2(std::vector<u8> const& data) {return __calc_hash<std::array<u8, MD5LEN>>(data, CALG_MD2, PROV_RSA_FULL);}
std::array<u8, MD5LEN> pwn::crypto::md4(std::vector<u8> const& data) {return __calc_hash<std::array<u8, MD5LEN>>(data, CALG_MD4, PROV_RSA_FULL);}
std::array<u8, MD5LEN> pwn::crypto::md5(std::vector<u8> const& data) {return __calc_hash<std::array<u8, MD5LEN>>(data, CALG_MD5, PROV_RSA_FULL);}
std::array<u8, SHA1LEN> pwn::crypto::sha1(std::vector<u8> const& data) {return __calc_hash<std::array<u8, SHA1LEN>>(data, CALG_SHA1, PROV_RSA_FULL);}
std::array<u8, SHA256LEN> pwn::crypto::sha256(std::vector<u8> const& data) {return __calc_hash<std::array<u8, SHA256LEN>>(data, CALG_SHA_256, PROV_RSA_AES);}
std::array<u8, SHA512LEN> pwn::crypto::sha512(std::vector<u8> const& data) {return __calc_hash<std::array<u8, SHA512LEN>>(data, CALG_SHA_512, PROV_RSA_AES);}
#endif