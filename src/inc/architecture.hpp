#pragma once

#include <algorithm>
#include <array>
#include <cwctype>
#include <format>
#include <iostream>
#include <stdexcept>
#include <string>

#include "common.hpp"


///
/// @brief Endianess class definition, with its wstring representation
///
enum class Endianess : uint8_t
{
    unknown,
    little,
    big,
};


///
/// @brief Types of architecture
///
enum class ArchitectureType : uint8_t
{
    unknown,
    x86,
    x64,
    arm,
    arm_thumb,
    arm64,
    mips,
    mips64,
    max
};


///
/// @brief Architecture class definition, with its wstring representation
///
struct Architecture
{
    std::string_view name;
    ArchitectureType id;
    usize ptrsize;
    Endianess endian;

    auto
    operator<=>(Architecture const& other) const = default;

    friend std::ostream&
    operator<<(std::ostream& os, Architecture const& a);

    friend std::wostream&
    operator<<(std::wostream& wos, Architecture const& a);

    static Architecture
    Find(std::string_view const& sv);
};

static constexpr std::array<std::pair<std::string_view, Architecture>, 2> Architectures {{
    {"x64", {"x64", ArchitectureType::x64, 8, Endianess::little}},
    {"x86", {"x86", ArchitectureType::x86, 4, Endianess::little}},
}};


///
/// toString()-like traits
///


// for Endianness

std::ostream&
operator<<(std::ostream& os, Endianess e);

std::wostream&
operator<<(std::wostream& wos, Endianess e);


template<>
struct std::formatter<Architecture, char> : std::formatter<std::string, char>
{
    auto
    format(Architecture a, format_context& ctx)
    {
        auto arch_name = std::string(a.name);
        std::transform(
            arch_name.begin(),
            arch_name.end(),
            arch_name.begin(),
            [](unsigned char c)
            {
                return std::toupper(c);
            });
        return std::formatter<string, char>::format(std::format("{}_{}_ENDIAN", arch_name, a.endian), ctx);
    }
};

template<>
struct std::formatter<Endianess, char> : std::formatter<std::string, char>
{
    auto
    format(Endianess a, format_context& ctx)
    {
        const char* e = (a == Endianess::little) ? "LITTLE" : (a == Endianess::big) ? "BIG" : "UNKNOWN";
        return formatter<string, char>::format(std::format("{}", e), ctx);
    }
};
