#include "Crypto.hpp"
#include "Handle.hpp"
#include "Log.hpp"

extern "C"
{
#include "mk_lib_crypto_hash_stream_md2.h"
#include "mk_lib_crypto_hash_stream_md4.h"
#include "mk_lib_crypto_hash_stream_md5.h"
#include "mk_lib_crypto_hash_stream_sha1.h"
#include "mk_lib_crypto_hash_stream_sha2_256.h"
#include "mk_lib_crypto_hash_stream_sha2_512.h"
}


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
Crypto::CRC8(std::vector<u8> const& data)
{
    return crc_base<u8>(data, CRC8_VARIANT);
}


u16
Crypto::CRC16(std::vector<u8> const& data)
{
    return crc_base<u16>(data, CRC16_VARIANT);
}


u32
Crypto::CRC32(std::vector<u8> const& data)
{
    return crc_base<u32>(data, CRC32_VARIANT);
}


u64
Crypto::CRC64(std::vector<u8> const& data)
{
    return crc_base<u64>(data, CRC64_VARIANT);
}


PWNAPI auto
Crypto::MD2(std::vector<u8> const& data) -> std::array<u8, Crypto::MD2LEN>
{
    std::array<u8, Crypto::MD2LEN> hash {};
    mk_lib_crypto_hash_stream_md2_t hasher {};
    mk_lib_crypto_hash_block_md2_digest_t digest {};

    ::mk_lib_crypto_hash_stream_md2_init(&hasher);
    ::mk_lib_crypto_hash_stream_md2_append(&hasher, data.data(), data.size());
    ::mk_lib_crypto_hash_stream_md2_finish(&hasher, &digest);

    ::memcpy(hash.data(), reinterpret_cast<u8*>(&digest), hash.size());
    return hash;
}

PWNAPI auto
Crypto::MD4(std::vector<u8> const& data) -> std::array<u8, Crypto::MD4LEN>
{
    std::array<u8, Crypto::MD4LEN> hash {};
    mk_lib_crypto_hash_stream_md4_t hasher {};
    mk_lib_crypto_hash_block_md4_digest_t digest {};

    ::mk_lib_crypto_hash_stream_md4_init(&hasher);
    ::mk_lib_crypto_hash_stream_md4_append(&hasher, data.data(), data.size());
    ::mk_lib_crypto_hash_stream_md4_finish(&hasher, &digest);

    ::memcpy(hash.data(), reinterpret_cast<u8*>(&digest), hash.size());
    return hash;
}

PWNAPI auto
Crypto::MD5(std::vector<u8> const& data) -> std::array<u8, Crypto::MD5LEN>
{
    std::array<u8, Crypto::MD5LEN> hash {};
    mk_lib_crypto_hash_stream_md5_t hasher {};
    mk_lib_crypto_hash_block_md5_digest_t digest {};

    ::mk_lib_crypto_hash_stream_md5_init(&hasher);
    ::mk_lib_crypto_hash_stream_md5_append(&hasher, data.data(), data.size());
    ::mk_lib_crypto_hash_stream_md5_finish(&hasher, &digest);

    ::memcpy(hash.data(), reinterpret_cast<u8*>(&digest), hash.size());
    return hash;
}

PWNAPI auto
Crypto::SHA1(std::vector<u8> const& data) -> std::array<u8, Crypto::SHA1LEN>
{
    std::array<u8, Crypto::SHA1LEN> hash {};
    mk_lib_crypto_hash_stream_sha1_t hasher {};
    mk_lib_crypto_hash_block_sha1_digest_t digest {};

    ::mk_lib_crypto_hash_stream_sha1_init(&hasher);
    ::mk_lib_crypto_hash_stream_sha1_append(&hasher, data.data(), data.size());
    ::mk_lib_crypto_hash_stream_sha1_finish(&hasher, &digest);

    ::memcpy(hash.data(), reinterpret_cast<u8*>(&digest), hash.size());
    return hash;
}

PWNAPI auto
Crypto::SHA256(std::vector<u8> const& data) -> std::array<u8, Crypto::SHA256LEN>
{
    std::array<u8, Crypto::SHA256LEN> hash {};
    mk_lib_crypto_hash_stream_sha2_256_t hasher {};
    mk_lib_crypto_hash_block_sha2_256_digest_t digest {};

    ::mk_lib_crypto_hash_stream_sha2_256_init(&hasher);
    ::mk_lib_crypto_hash_stream_sha2_256_append(&hasher, data.data(), data.size());
    ::mk_lib_crypto_hash_stream_sha2_256_finish(&hasher, &digest);

    ::memcpy(hash.data(), reinterpret_cast<u8*>(&digest), hash.size());
    return hash;
}

PWNAPI auto
Crypto::SHA512(std::vector<u8> const& data) -> std::array<u8, Crypto::SHA512LEN>
{
    std::array<u8, Crypto::SHA512LEN> hash {};
    mk_lib_crypto_hash_stream_sha2_512_t hasher {};
    mk_lib_crypto_hash_block_sha2_512_digest_t digest {};

    ::mk_lib_crypto_hash_stream_sha2_512_init(&hasher);
    ::mk_lib_crypto_hash_stream_sha2_512_append(&hasher, data.data(), data.size());
    ::mk_lib_crypto_hash_stream_sha2_512_finish(&hasher, &digest);

    ::memcpy(hash.data(), reinterpret_cast<u8*>(&digest), hash.size());
    return hash;
}
