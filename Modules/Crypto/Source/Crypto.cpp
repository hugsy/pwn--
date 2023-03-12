#include "Crypto.hpp"

#include "Log.hpp"

using namespace pwn;

///
///
/// @note Those are NOT valid CRC implementations!! Use https://en.wikipedia.org/wiki/Cyclic_redundancy_check for that
/// I used those for fast hashing, not for redundancy check.
///
///

template<typename T>
static T
crc_base(std::vector<u8> const& data, T variant)
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

constexpr u8 CRC8_VARIANT   = 0xE5;
constexpr u16 CRC16_VARIANT = 0x8408;
constexpr u32 CRC32_VARIANT = 0xEDB88320;
constexpr u64 CRC64_VARIANT = 0xC96C5795D7870F42;


u8
Crypto::crc8(std::vector<u8> const& data)
{
    return crc_base<u8>(data, CRC8_VARIANT);
}


u16
Crypto::crc16(std::vector<u8> const& data)
{
    return crc_base<u16>(data, CRC16_VARIANT);
}


u32
Crypto::crc32(std::vector<u8> const& data)
{
    return crc_base<u32>(data, CRC32_VARIANT);
}


u64
Crypto::crc64(std::vector<u8> const& data)
{
    return crc_base<u64>(data, CRC64_VARIANT);
}


#ifdef PWN_BUILD_FOR_WINDOWS
#include <bcrypt.h>

template<typename T>
static T
Hash(std::vector<u8> const& data, LPCWSTR const AlgoId)
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

std::array<u8, Crypto::MD5LEN>
Crypto::md2(std::vector<u8> const& data)
{
    return Hash<std::array<u8, Crypto::MD5LEN>>(data, BCRYPT_MD2_ALGORITHM);
}

std::array<u8, Crypto::MD5LEN>
Crypto::md4(std::vector<u8> const& data)
{
    return Hash<std::array<u8, Crypto::MD5LEN>>(data, BCRYPT_MD4_ALGORITHM);
}

std::array<u8, Crypto::MD5LEN>
Crypto::md5(std::vector<u8> const& data)
{
    return Hash<std::array<u8, Crypto::MD5LEN>>(data, BCRYPT_MD5_ALGORITHM);
}
std::array<u8, Crypto::SHA1LEN>
Crypto::sha1(std::vector<u8> const& data)
{
    return Hash<std::array<u8, Crypto::SHA1LEN>>(data, BCRYPT_SHA1_ALGORITHM);
}

std::array<u8, Crypto::SHA256LEN>
Crypto::sha256(std::vector<u8> const& data)
{
    return Hash<std::array<u8, Crypto::SHA256LEN>>(data, BCRYPT_SHA256_ALGORITHM);
}

std::array<u8, Crypto::SHA512LEN>
Crypto::sha512(std::vector<u8> const& data)
{
    return Hash<std::array<u8, Crypto::SHA512LEN>>(data, BCRYPT_SHA512_ALGORITHM);
}

#else

//
// TODO: make md/sha portable to linux too
//

#endif
