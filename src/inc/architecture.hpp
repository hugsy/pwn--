#pragma once

#include "pch.hpp"


///
/// @brief Endianess class definition, with its wstring representation
///
enum class Endianess
{
    unknown,
    little,
    big,
};


///
/// @brief Architecture class definition, with its wstring representation
///

enum class ArchitectureType
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


class Architecture
{
public:
    constexpr Architecture() noexcept :
        m_id(ArchitectureType::unknown),
        m_name(L""),
        m_ptrsize(0),
        m_endianess(Endianess::unknown)
    {
    }

    constexpr Architecture(ArchitectureType id, const std::wstring& name, size_t ptrsize, Endianess endian) noexcept :
        m_id(id),
        m_name(name),
        m_ptrsize(ptrsize),
        m_endianess(endian)
    {
    }

    constexpr const ArchitectureType
    id() const
    {
        return m_id;
    }

    constexpr const std::wstring_view&
    name() const
    {
        return m_name;
    }

    constexpr size_t
    ptrsize() const
    {
        return m_ptrsize;
    }

    constexpr Endianess
    endian() const
    {
        return m_endianess;
    }

private:
    const ArchitectureType m_id;
    const size_t m_ptrsize;
    const std::wstring_view m_name;
    const Endianess m_endianess;
};


const std::map<ArchitectureType, std::shared_ptr<Architecture>> Architectures = {

#define AddArchitecture(__i, __n, __p, __e)                                                                            \
    {                                                                                                                  \
        ArchitectureType::__i, std::make_shared<Architecture>(ArchitectureType::__i, __n, __p, Endianess::__e)         \
    }

    AddArchitecture(x86, L"x86", 4, little),
    AddArchitecture(x64, L"x86-64", 8, little),
    AddArchitecture(arm, L"ARM", 4, little),
    AddArchitecture(arm_thumb, L"ARM-Thumb", 2, little),
    AddArchitecture(arm64, L"AARCH64", 8, little),
    AddArchitecture(mips, L"MIPS", 4, little),
    AddArchitecture(mips64, L"MIPS64", 8, little),

#undef AddArchitecture
};


///
/// toString()-like traits
///

std::wostream&
operator<<(std::wostream& wos, Architecture const& a);


std::wostream&
operator<<(std::wostream& wos, Endianess e);
