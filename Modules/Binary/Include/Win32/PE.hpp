#pragma once

#include <span>

#include "Common.hpp"


template<class... Ts>
struct overloaded : Ts...
{
    using Ts::operator()...;
};


namespace pwn::Binary
{

class PE
{
public:
    using DosHeader          = IMAGE_DOS_HEADER;
    using PeHeader32         = IMAGE_NT_HEADERS32;
    using PeHeader64         = IMAGE_NT_HEADERS64;
    using PeHeader           = std::variant<PeHeader32, PeHeader64>;
    using PeFileHeader       = IMAGE_FILE_HEADER;
    using PeOptionalHeader32 = IMAGE_OPTIONAL_HEADER32;
    using PeOptionalHeader64 = IMAGE_OPTIONAL_HEADER64;
    using PeOptionalHeader   = std::variant<PeOptionalHeader32, PeOptionalHeader64>;
    using PeSectionHeader    = IMAGE_SECTION_HEADER;
    using PeDataDirectory    = IMAGE_DATA_DIRECTORY;
    using PeExportDirectory  = IMAGE_EXPORT_DIRECTORY;
    using PeArchitecture     = IMAGE_ARCHITECTURE_ENTRY;

    struct PeExportEntry
    {
        u16 Ordinal;
        u32 Rva;
        u32 NameOffset;
        std::string Name;
    };


    ///
    ///@brief
    ///
    ///@param Path
    ///@return Result<bool>
    ///
    static Result<PE>
    Parse(std::filesystem::path const& Path)
    {
        PE pe {Path};
        if ( !(bool)pe )
        {
            return Err(ErrorCode::MalformedFile);
        }

        return Ok(pe);
    }


    ///
    ///@brief Construct a new PE object from a path
    ///
    ///@param Path
    ///
    PE(std::filesystem::path const& Path);


    ///
    ///@brief Construct a new PE object from an offset and size
    ///
    ///@param Offset
    ///@param Size
    ///
    PE(uptr Offset, usize Size);


    operator bool() const
    {
        return IsValid();
    }

    bool
    IsValid() const
    {
        return m_IsValid;
    }

    DosHeader const&
    Dos() const
    {
        return m_DosHeader;
    }

    bool
    Is64b() const
    {
        return m_Is64b;
    }


    PeHeader const&
    Header() const
    {
        return m_PeHeader;
    }


    std::vector<PeDataDirectory> const&
    DataDirectories() const
    {
        return m_PeDataDirectories;
    }


    std::vector<PeSectionHeader> const&
    Sections() const
    {
        return m_PeSections;
    }


    PeArchitecture const&
    Architecture() const
    {
        return m_PeArchitecture;
    }

    std::vector<PeExportEntry> const&
    ExportTable() const
    {
        return m_PeExportDirectory.Entries;
    }

private:
    bool
    ParsePeFromMemory(std::span<u8> const& View);


    uptr
    Base() const
    {
        return m_NtBase;
    }


    template<class T = void*>
    T const
    VA(uptr Offset) const
    {
        return reinterpret_cast<T>(Base() + Offset);
    }


    uptr
    RVA(uptr Offset) const
    {
        return Offset - Base();
    }

    PE::PeSectionHeader*
    FirstSection();


    bool
    FillSections();


    bool
    FillDataDirectories();


    bool
    FillExportTable();


    bool
    FillImportTable();


    bool
    FillResources();


    bool
    FillException();


    bool
    FillSecurity();


    bool
    FillRelocations();


    bool
    FillArchitecture();


    bool
    FillThreadLocalStorage();


    bool
    FillLoadConfiguration();


    bool
    FillDebug();


    bool
    FillGlobalPointer();

    bool
    FillBoundImport();


    bool
    FillImportAddressTable();


    bool
    FillDelayImport();


    bool
    FillComDescriptor();


    ///
    ///@brief Find a section header from a relative virtual address
    ///
    ///@param Rva
    ///@return Result<PE::PeSectionHeader>
    ///
    Result<PE::PeSectionHeader>
    FindSectionFromRva(uptr Rva);


    ///
    ///@brief Given a relative virtual address and a directory index, determine the virtual address
    ///
    ///@param Rva
    ///@param DirectoryIndex
    ///@return uptr
    ///
    uptr
    GetVirtualAddress(uptr Rva, u8 DirectoryIndex);


    bool m_IsValid {false};
    uptr m_MaxPeVa {0};
    DosHeader m_DosHeader {};
    PeHeader m_PeHeader {};
    uptr m_DosBase {0}, m_NtBase {0};
    bool m_Is64b {false};
    std::vector<PeDataDirectory> m_PeDataDirectories {};
    std::vector<PeSectionHeader> m_PeSections {};

    struct
    {
        PeExportDirectory Header;
        std::vector<PeExportEntry> Entries;
    } m_PeExportDirectory {};

    PeArchitecture m_PeArchitecture;
};

} // namespace pwn::Binary
