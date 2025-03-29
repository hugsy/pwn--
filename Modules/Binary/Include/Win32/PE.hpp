#pragma once

#include <span>
#include <variant>

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
#pragma region PE Classes Redefinition
    enum class ResourceType
    {
        WideString,
        String,
        Bitmap,
        Icon,
        Menu,
        Raw
    };


#pragma pack(push, 1)
    using DosHeader                = IMAGE_DOS_HEADER;
    using PeHeader32               = IMAGE_NT_HEADERS32;
    using PeHeader64               = IMAGE_NT_HEADERS64;
    using PeHeader                 = std::variant<PeHeader32, PeHeader64>;
    using PeFileHeader             = IMAGE_FILE_HEADER;
    using PeOptionalHeader32       = IMAGE_OPTIONAL_HEADER32;
    using PeOptionalHeader64       = IMAGE_OPTIONAL_HEADER64;
    using PeOptionalHeader         = std::variant<IMAGE_OPTIONAL_HEADER32, IMAGE_OPTIONAL_HEADER64>;
    using PeSectionHeader          = IMAGE_SECTION_HEADER;
    using PeDataDirectory          = IMAGE_DATA_DIRECTORY;
    using PeExportDirectory        = IMAGE_EXPORT_DIRECTORY;
    using PeArchitecture           = IMAGE_ARCHITECTURE_ENTRY;
    using PeResourceDirectoryEntry = IMAGE_RESOURCE_DIRECTORY_ENTRY;
    using PeResourceDataEntry      = IMAGE_RESOURCE_DATA_ENTRY;

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
        // TODO: ImpHash, ExpHash, IatHash
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

    using ResourceEntryString     = std::string;
    using ResourceEntryWideString = std::wstring;
    struct ResourceEntryRaw : PeResourceDataEntry
    {
    };

    struct ResourceEntry : PeResourceDataEntry
    {
        PE::ResourceType Type;
        std::variant<ResourceEntryRaw, ResourceEntryString, ResourceEntryWideString> Data;
    };

    struct PeResourceDirectory : IMAGE_RESOURCE_DIRECTORY
    {
        std::vector<ResourceEntry> Entries;
    };

    struct PeExceptionTableEntry : IMAGE_RUNTIME_FUNCTION_ENTRY
    {
#if defined(_ARM_) || defined(_ARM64_)
        DWORD EndAddress {};
#endif
        usize Size;
        std::vector<u8> UnwindRawBytes;
    };

    struct PeImageBaseRelocation : IMAGE_BASE_RELOCATION
    {
        struct RelocationEntry
        {
            u16 Type {};
            u32 Address {};
            std::string_view TypeName {};
        };

        usize NumberOfEntries {};
        std::vector<RelocationEntry> Entries {};
    };

    struct PeDebugEntry : IMAGE_DEBUG_DIRECTORY
    {
        std::string_view TypeName {};
        std::vector<u8> RawData {};
    };

    struct PeDotNetMetadataStreamHeader
    {
        u32 Offset {};
        u32 Size {};
        std::string Name {};
    };

    struct PeComDescriptor : IMAGE_COR20_HEADER
    {
        //
        // Metadata
        //
        u32 Signature {};
        u16 MajorVersion {};
        u16 MinorVersion {};
        u32 Reserved {};
        u32 Length {};
        std::string VersionString {};
        u16 Flags {};
        u16 Streams {};

        //
        // Streams
        //
        std::vector<PeDotNetMetadataStreamHeader> StreamHeaders {};
    };

    struct PeLoadConfigDirectory
    {
        std::variant<IMAGE_LOAD_CONFIG_DIRECTORY32, IMAGE_LOAD_CONFIG_DIRECTORY64> Header;
    };

#pragma pack(pop)

#pragma endregion

    PE() = default;


    ///
    ///@brief Construct a new PE object from a path
    ///
    ///@param Path the path to the file on disk to be parsed
    ///
    PE(std::filesystem::path const& Path);


    ///
    ///@brief Construct a new PE object from an offset and size
    ///
    ///@param Offset
    ///@param Size
    ///
    PE(uptr Offset, usize Size);


    ///
    ///@brief The DOS header address *when* the image was parsed, the address is not guaranteed to be still mapped later
    ///
    ///@return DosHeader const&
    ///
    DosHeader const&
    Dos() const
    {
        return m_DosHeader;
    }

    ///
    ///@brief
    ///
    ///@return true
    ///@return false
    ///
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

    uptr const
    EntryPointAddress() const
    {
        auto const hdrs = Header();
        return Is64b() ? std::get<PeHeader64>(hdrs).OptionalHeader.AddressOfEntryPoint :
                         std::get<PeHeader32>(hdrs).OptionalHeader.AddressOfEntryPoint;
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

    std::vector<PeImportDescriptor> const&
    ImportTable() const
    {
        return m_PeImportTable.Entries;
    }

    std::vector<PeExceptionTableEntry> const&
    ExceptionTable() const
    {
        return m_PeExceptionTable.Entries;
    }

    std::vector<PeDelayLoadDescriptor> const&
    DelayLoadTable() const
    {
        return m_PeDelayImportTable.Entries;
    }

    std::vector<PeDebugEntry> const&
    DebugTable() const
    {
        return m_PeDebugTable;
    }

private:
    bool
    ParsePeFromMemory(std::span<u8> const& View);


    uptr
    Base() const
    {
        return m_NtBase;
    }

    template<typename T>
    bool
    IsWithinBounds(const T& Address) const;


    ///
    ///@brief Get a raw pointer to the first section
    ///
    ///@return PE::PeSectionHeader*
    ///
    PE::PeSectionHeader*
    FirstSection() const;


    ///
    ///@brief Populate the PE section entries
    ///
    ///@return true
    ///@return false if any error occured
    ///
    bool
    FillSections();


    ///
    ///@brief Fill the ExportTable table
    ///
    ///@return true
    ///@return false if any error occured
    ///
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
    /// @link https://github.com/dotnet/core/blob/main/Documentation/diagnostics/portable_pdb.md
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
    ///@brief Generic templated function to find a Section Header from a predicate
    ///
    ///@tparam Pred
    ///@param Condition
    ///@return Result<PE::PeSectionHeader>
    ///
    template<typename Pred>
    Result<PE::PeSectionHeader>
    FindSection(Pred Condition);


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
    Result<PeDelayLoadDescriptor>
    BuildDelayImportEntry(const IMAGE_DELAYLOAD_DESCRIPTOR* Descriptor);


private:
    uptr m_PeMaxVa {0};
    uptr m_DosBase {0}, m_NtBase {0};
    bool m_Is64b {false};
    DosHeader m_DosHeader {};
    PeHeader m_PeHeader {};
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

    struct
    {
        std::vector<PeExceptionTableEntry> Entries;
    } m_PeExceptionTable {};

    std::vector<PeImageBaseRelocation> m_PeRelocations {};

    PeComDescriptor m_PeComDescriptor {};

    std::vector<PeDebugEntry> m_PeDebugTable {};

    PeLoadConfigDirectory m_PeLoadConfigDirectory {};
};

} // namespace pwn::Binary
