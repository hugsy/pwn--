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
    using DosHeader                = IMAGE_DOS_HEADER;
    using PeHeader32               = IMAGE_NT_HEADERS32;
    using PeHeader64               = IMAGE_NT_HEADERS64;
    using PeHeader                 = std::variant<PeHeader32, PeHeader64>;
    using PeFileHeader             = IMAGE_FILE_HEADER;
    using PeOptionalHeader32       = IMAGE_OPTIONAL_HEADER32;
    using PeOptionalHeader64       = IMAGE_OPTIONAL_HEADER64;
    using PeOptionalHeader         = std::variant<PeOptionalHeader32, PeOptionalHeader64>;
    using PeSectionHeader          = IMAGE_SECTION_HEADER;
    using PeDataDirectory          = IMAGE_DATA_DIRECTORY;
    using PeExportDirectory        = IMAGE_EXPORT_DIRECTORY;
    using PeResourceDirectory      = IMAGE_RESOURCE_DIRECTORY;
    using PeArchitecture           = IMAGE_ARCHITECTURE_ENTRY;
    using PeResourceDirectoryEntry = IMAGE_RESOURCE_DIRECTORY_ENTRY;
    using PeResourceDataEntry      = IMAGE_RESOURCE_DATA_ENTRY;


#pragma pack(push, 1)
    struct PeThunkData32 : IMAGE_THUNK_DATA32
    {
        u16 Hint;
        std::string Name;
    };

    struct PeThunkData64 : IMAGE_THUNK_DATA64
    {
        u16 Hint;
        std::string Name;
    };

    using PeThunkData = std::variant<PeThunkData32, PeThunkData64>;

    struct PeImportDescriptor : IMAGE_IMPORT_DESCRIPTOR
    {
        std::string Name2;
        std::vector<PeThunkData> Functions;
        // TODO: (Imp)Hash
    };

    struct PeDelayLoadDescriptor : IMAGE_DELAYLOAD_DESCRIPTOR
    {
        std::string DllName;
        u32 ModuleHandle;
        std::vector<PeThunkData> Functions;
    };

    struct PeExportEntry
    {
        u16 Ordinal;
        u32 Rva;
        u32 NameOffset;
        std::string Name;
    };

    struct PeResourceDirectory : IMAGE_RESOURCE_DIRECTORY
    {
        std::vector<PeResourceDataEntry> Entries;
    };
#pragma pack(pop)


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


    ///
    /// @brief Fill the ExportTable section of the PE
    ///
    /// @return true
    /// @return false
    ///
    bool
    FillExportTable();


    ///
    /// @brief Fill the ImportTable section of the PE
    ///
    /// @return true
    /// @return false
    ///
    bool
    FillImportTable();


    ///
    /// @brief Fill the Resources section of the PE
    ///
    /// @return true
    /// @return false
    ///
    bool
    FillResources();


    ///
    /// @brief Fill the Exception section of the PE
    ///
    /// @return true
    /// @return false
    ///
    bool
    FillException();


    ///
    /// @brief Fill the Security section of the PE
    ///
    /// @return true
    /// @return false
    ///
    bool
    FillSecurity();


    ///
    /// @brief Fill the Relocations section of the PE
    ///
    /// @return true
    /// @return false
    ///
    bool
    FillRelocations();


    ///
    /// @brief Fill the Architecture section of the PE
    ///
    /// @return true
    /// @return false
    ///
    bool
    FillArchitecture();


    ///
    /// @brief Fill the ThreadLocalStorage section of the PE
    ///
    /// @return true
    /// @return false
    ///
    bool
    FillThreadLocalStorage();


    ///
    /// @brief Fill the LoadConfiguration section of the PE
    ///
    /// @return true
    /// @return false
    ///
    bool
    FillLoadConfiguration();


    ///
    /// @brief Fill the Debug section of the PE
    ///
    /// @return true
    /// @return false
    ///
    bool
    FillDebug();


    ///
    /// @brief Fill the GlobalPointer section of the PE
    ///
    /// @return true
    /// @return false
    ///
    bool
    FillGlobalPointer();


    ///
    /// @brief Fill the Bound Import section of the PE
    ///
    /// @return true
    /// @return false
    ///
    bool
    FillBoundImport();


    ///
    /// @brief Fill the Import Address Table section of the PE
    ///
    /// @return true
    /// @return false
    ///
    bool
    FillImportAddressTable();


    ///
    /// @brief Fill the Delay Load section of the PE
    ///
    /// @return true
    /// @return false
    ///
    bool
    FillDelayImport();


    ///
    /// @brief Fill the COM Descriptor section of the PE
    ///
    /// @return true
    /// @return false
    ///
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


    ///
    ///@brief
    ///
    ///@tparam T1
    ///@tparam T2
    ///@param Name
    ///@param Descriptor
    ///@return PeImportDescriptor
    ///
    template<typename T1, typename T2>
    PeImportDescriptor
    BuildImportEntry(const char* Name, const IMAGE_IMPORT_DESCRIPTOR* Descriptor);


    ///
    ///@brief
    ///
    ///@tparam T1
    ///@tparam T2
    ///@param Name
    ///@param Descriptor
    ///@return PeDelayLoadDescriptor
    ///
    template<typename T1, typename T2>
    PeDelayLoadDescriptor
    BuildDelayImportEntry(const char* DllName, const IMAGE_DELAYLOAD_DESCRIPTOR* Descriptor);


    bool m_IsValid {false};
    uptr m_PeMaxVa {0};
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

    struct
    {
        std::vector<PeImportDescriptor> Entries;
    } m_PeImportTable {};

    struct
    {
        std::vector<PeDelayLoadDescriptor> Entries;
    } m_PeDelayImportTable {};

    PeArchitecture m_PeArchitecture {};
    PeResourceDirectory m_PeResourceDirectory {};
};

} // namespace pwn::Binary
