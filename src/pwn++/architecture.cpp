#include "architecture.hpp"

std::ostream&
operator<<(std::ostream& wos, Architecture const& a)
{
    switch ( a.id )
    {
    case ArchitectureType::x86:
        wos << "i386";
        break;
    case ArchitectureType::x64:
        wos << "x86-64";
        break;
    case ArchitectureType::arm:
        wos << "ARM";
        break;
    case ArchitectureType::arm_thumb:
        wos << "ARM (Thumb mode)";
        break;
    case ArchitectureType::arm64:
        wos << "AARCH64";
        break;
    case ArchitectureType::mips:
        wos << "MIPS";
        break;
    default:
        wos.setstate(std::ios_base::failbit);
    }
    return wos;
}


std::ostream&
operator<<(std::ostream& wos, Endianess e)
{
    switch ( e )
    {
    case Endianess::little:
        wos << "little";
        break;
    case Endianess::big:
        wos << "big";
        break;
    default:
        wos.setstate(std::ios_base::failbit);
    }
    return wos;
}


std::wostream&
operator<<(std::wostream& wos, Architecture const& a)
{
    switch ( a.id )
    {
    case ArchitectureType::x86:
        wos << L"i386";
        break;
    case ArchitectureType::x64:
        wos << L"x86-64";
        break;
    case ArchitectureType::arm:
        wos << L"ARM";
        break;
    case ArchitectureType::arm_thumb:
        wos << L"ARM (Thumb mode)";
        break;
    case ArchitectureType::arm64:
        wos << L"AARCH64";
        break;
    case ArchitectureType::mips:
        wos << L"MIPS";
        break;
    default:
        wos.setstate(std::ios_base::failbit);
    }
    return wos;
}


std::wostream&
operator<<(std::wostream& wos, Endianess e)
{
    switch ( e )
    {
    case Endianess::little:
        wos << L"little";
        break;
    case Endianess::big:
        wos << L"big";
        break;
    default:
        wos.setstate(std::ios_base::failbit);
    }
    return wos;
}
