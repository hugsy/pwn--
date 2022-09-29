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
    std::wstring_view name;
    ArchitectureType id;
    std::size_t ptrsize;
    Endianess endian;

    auto
    operator<=>(Architecture const& other) const = default;
};


static constexpr std::array<std::pair<std::wstring_view, Architecture>, 2> Architectures {{
    {L"x64", {L"x64", ArchitectureType::x64, 8, Endianess::little}},
    {L"x86", {L"x86", ArchitectureType::x86, 4, Endianess::little}},
}};


Architecture static inline lookup_architecture(std::wstring_view const& sv)
{
    static constexpr auto map = CMap<std::wstring_view, Architecture, Architectures.size()> {{Architectures}};
    return map.at(sv);
}


///
/// toString()-like traits
///


// for Architecture
std::wostream&
operator<<(std::wostream& wos, Architecture const& a);

template<>
struct std::formatter<Architecture, wchar_t> : std::formatter<std::wstring, wchar_t>
{
    auto
    format(Architecture a, wformat_context& ctx)
    {
        std::wstring arch {a.name};
        std::transform(arch.begin(), arch.end(), arch.begin(), std::towupper);
        return std::formatter<wstring, wchar_t>::format(std::format(L"{}_{}_ENDIAN", arch, a.endian), ctx);
    }
};


// for Endianness
std::wostream&
operator<<(std::wostream& wos, Endianess e);

template<>
struct std::formatter<Endianess, wchar_t> : std::formatter<std::wstring, wchar_t>
{
    auto
    format(Endianess a, wformat_context& ctx)
    {
        const wchar_t* e = (a == Endianess::little) ? L"LITTLE" : (a == Endianess::big) ? L"BIG" : L"UNKNOWN";
        return formatter<wstring, wchar_t>::format(std::format(L"{}", e), ctx);
    }
};
