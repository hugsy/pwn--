#pragma once
#include "Common.hpp"


namespace pwn::literals
{
constexpr static std::uint32_t
convert_substring_to_int(const char* str, int offset)
{
    return static_cast<std::uint32_t>(str[offset] - '0') * 10 + static_cast<std::uint32_t>(str[offset + 1] - '0');
}

constexpr char key = convert_substring_to_int(__TIME__, 0) ^ convert_substring_to_int(__TIME__, 3) ^
                     convert_substring_to_int(__TIME__, 6);


///
/// @brief Convenience wrapper to represent size in bytes
///
/// @param x
/// @return usize
///
auto constexpr
operator""_B(unsigned long long x) noexcept -> usize
{
    return x;
}

///
/// @brief Convenience wrapper to represent size in kilobytes
///
/// @param x
/// @return usize
///
auto constexpr
operator""_KB(unsigned long long x) noexcept -> usize
{
    return 1024 * x;
}

///
/// @brief Convenience wrapper to represent size in megabytes
///
/// @param x
/// @return usize
///
auto constexpr
operator""_MB(unsigned long long x) noexcept -> usize
{
    return 1024 * 1024 * x;
}

///
/// @brief Convenience wrapper to represent size in gigabytes
///
/// @param x
/// @return usize
///
auto constexpr
operator""_GB(unsigned long long x) noexcept -> usize
{
    return 1024 * 1024 * 1024 * x;
}


///
/// @brief Lightweight wrapper class to decode strings
///
struct encoded_string
{
    const std::string m_str {};
    constexpr const std::string
    str() const noexcept
    {
        std::string b {m_str};
        for ( char i = 0; auto& c : b )
            c ^= key + (i++);
        return b;
    }
};


///
/// @brief constexpr strings obfuscator
///
/// @param str
/// @param t
/// @return constexpr encoded_string
///
constexpr encoded_string
operator""_es(const char* str, std::size_t t)
{
    return {[&str, &t]()
            {
                std::string b {str, t};
                for ( char i = 0; auto& c : b )
                    c ^= key + (i++);
                return b;
            }()};
}


} // namespace pwn::literals
