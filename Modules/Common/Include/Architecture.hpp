#pragma once


#include "Common.hpp"


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
///@brief Output Endianess to std::ostream
///
///@param os
///@param e
///@return std::ostream&
///
std::ostream&
operator<<(std::ostream& os, Endianess e);

///
///@brief Output Endianess to std::wostream
///
///@param wos
///@param e
///@return std::wostream&
///
std::wostream&
operator<<(std::wostream& wos, Endianess e);


///
/// @brief Types of architecture
///
enum class ArchitectureType : uint8_t
{
    unknown,
    x86,
    x64,
    arm64,
    arm,
    arm_thumb,
    mips,
    mips64,
    max
};


///
/// @brief Architecture class definition, with its wstring representation
///
struct Architecture
{
    std::string_view name {};
    ArchitectureType id {};
    usize ptrsize {};
    Endianess endian {};

    auto
    operator<=>(Architecture const& other) const = default;

    ///
    ///@brief Output Architecture to std::wostream
    ///
    ///@param wos
    ///@param e
    ///@return std::wostream&
    ///
    friend std::ostream&
    operator<<(std::ostream& os, Architecture const& a);

    ///
    ///@brief Output Architecture to std::wostream
    ///
    ///@param wos
    ///@param e
    ///@return std::wostream&
    ///
    friend std::wostream&
    operator<<(std::wostream& wos, Architecture const& a);

    ///
    ///@brief Find an architecture by name. The function will throw `std::range_error`
    // if not found
    ///
    ///@param sv
    ///@return Architecture
    ///
    static Architecture
    Find(std::string_view const& sv);
};


///
///@brief Supported architecture declarations
///
static constexpr CMap<std::string_view, Architecture, 3> Architectures {
    {{
        {"x64"sv, {"X86_64"sv, ArchitectureType::x64, 8, Endianess::little}},
        {"x86"sv, {"X86_32"sv, ArchitectureType::x86, 4, Endianess::little}},
        {"arm64"sv, {"ARM_AARCH64"sv, ArchitectureType::arm64, 8, Endianess::little}},
    }},
};


///
///@brief Output Endianess to std::format
///
///@tparam
///
template<>
struct std::formatter<Endianess, char> : std::formatter<std::string, char>
{
    auto
    format(Endianess a, format_context& ctx)
    {
        const char* e = (a == Endianess::little) ? "LITTLE" : (a == Endianess::big) ? "BIG" : "UNKNOWN";
        return std::formatter<string, char>::format(std::format("{}", e), ctx);
    }
};


///
///@brief Output Architecture to std::format
///
///@tparam
///
template<>
struct std::formatter<Architecture, char> : std::formatter<std::string, char>
{
    auto
    format(Architecture a, std::format_context& ctx)
    {
        std::string arch_name;
        arch_name.resize(a.name.size());
        std::transform(
            a.name.cbegin(),
            a.name.cend(),
            arch_name.begin(),
            [](unsigned char c)
            {
                return std::toupper(c);
            });
        return std::formatter<string, char>::format(std::format("{}_{}_ENDIAN", arch_name, a.endian), ctx);
    }
};
