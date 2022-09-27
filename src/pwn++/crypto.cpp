#include "crypto.hpp"

#include "log.hpp"

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


#ifdef PWN_BUILD_FOR_WINDOWS
#include <bcrypt.h>

template<typename T>
static T
__calc_hash(std::vector<u8> const& data, LPCWSTR const AlgoId)
{
    T out               = {};
    const DWORD out_sz  = out.size() & 0xffffffff;
    const DWORD data_sz = data.size() & 0xffffffff;

    BCRYPT_ALG_HANDLE hAlgorithm;
    NTSTATUS Status = ::BCryptOpenAlgorithmProvider(&hAlgorithm, AlgoId, nullptr, 0);
    if ( NT_SUCCESS(Status) )
    {
        BCRYPT_HASH_HANDLE hHash;
        PUCHAR HashObject;
        Status = ::BCryptCreateHash(hAlgorithm, &hHash, nullptr, 0, nullptr, 0, 0);
        if ( NT_SUCCESS(Status) )
        {
            Status = ::BCryptHashData(hHash, (PUCHAR)data.data(), data_sz, 0);
            if ( NT_SUCCESS(Status) )
            {
                ::BCryptFinishHash(hHash, &out[0], out_sz, 0);
            }
        }
        ::BCryptCloseAlgorithmProvider(hAlgorithm, 0);
    }

    return out;
}

std::array<u8, MD5LEN>
pwn::crypto::md2(std::vector<u8> const& data)
{
    return __calc_hash<std::array<u8, MD5LEN>>(data, BCRYPT_MD2_ALGORITHM);
}

std::array<u8, MD5LEN>
pwn::crypto::md4(std::vector<u8> const& data)
{
    return __calc_hash<std::array<u8, MD5LEN>>(data, BCRYPT_MD4_ALGORITHM);
}

std::array<u8, MD5LEN>
pwn::crypto::md5(std::vector<u8> const& data)
{
    return __calc_hash<std::array<u8, MD5LEN>>(data, BCRYPT_MD5_ALGORITHM);
}
std::array<u8, SHA1LEN>
pwn::crypto::sha1(std::vector<u8> const& data)
{
    return __calc_hash<std::array<u8, SHA1LEN>>(data, BCRYPT_SHA1_ALGORITHM);
}

std::array<u8, SHA256LEN>
pwn::crypto::sha256(std::vector<u8> const& data)
{
    return __calc_hash<std::array<u8, SHA256LEN>>(data, BCRYPT_SHA256_ALGORITHM);
}

std::array<u8, SHA512LEN>
pwn::crypto::sha512(std::vector<u8> const& data)
{
    return __calc_hash<std::array<u8, SHA512LEN>>(data, BCRYPT_SHA512_ALGORITHM);
}

#else

//
// TODO: make md/sha portable to linux too
//

#endif
