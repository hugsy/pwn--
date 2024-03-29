#pragma once


#include "Common.hpp"
#include "Log.hpp"

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
    std::array<std::string_view, 4> aliases {};

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
    // if not found.
    ///
    ///@param architecture_name
    ///
    ///@return Architecture
    ///@throw range_error if not found
    ///
    static Architecture const&
    Find(std::string_view const& architecture_name);
};


///
///@brief Supported architecture declarations
///
static constexpr CMap<ArchitectureType, Architecture, 4> Architectures {
    {{
        {ArchitectureType::x64,
         {"x64"sv,
          ArchitectureType::x64,
          8,
          Endianess::little,
          {
              "x86-64"sv,
          }}},
        {ArchitectureType::x86,
         {"x86"sv,
          ArchitectureType::x86,
          4,
          Endianess::little,
          {
              "i386"sv,
          }}},
        {ArchitectureType::arm64, {"arm64"sv, ArchitectureType::arm64, 8, Endianess::little, {"aarch64"sv}}},
        {ArchitectureType::arm, {"arm"sv, ArchitectureType::arm, 4, Endianess::little}},
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
    template<typename FormatContext>
    auto
    format(Endianess a, FormatContext& ctx)
    {
        const char* e = (a == Endianess::little) ? "LITTLE" : (a == Endianess::big) ? "BIG" : "UNKNOWN";
        return std::formatter<std::string, char>::format(std::string(e), ctx);
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
    template<typename FormatContext>
    auto
    format(const Architecture& a, FormatContext& ctx) const
    {
        return std::formatter<std::string, char>::format(std::string(a.name), ctx);
    }
};
