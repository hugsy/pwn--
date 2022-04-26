#pragma once

#include <algorithm>
#include <array>
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
/// @brief Architecture class definition, with its wstring representation
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


struct Architecture
{
    ArchitectureType id;
    std::wstring_view name;
    size_t ptrsize;
    Endianess endian;
};


static constexpr std::array<std::pair<std::string_view, Architecture>, 2> Architectures {{
    {"x64", {ArchitectureType::x64, L"x64", 8, Endianess::little}},
    {"x86", {ArchitectureType::x86, L"x86", 4, Endianess::little}},
}};


Architecture static inline lookup_architecture(const std::string_view sv)
{
    static constexpr auto map = CMap<std::string_view, Architecture, Architectures.size()> {{Architectures}};
    return map.at(sv);
}


///
/// toString()-like traits
///

std::wostream&
operator<<(std::wostream& wos, Architecture const& a);


std::wostream&
operator<<(std::wostream& wos, Endianess e);
