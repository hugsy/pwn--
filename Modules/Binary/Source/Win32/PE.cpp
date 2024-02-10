#include <memory>

#include "Win32/FileSystem.hpp"
#include "Win32/PE.hpp"


namespace pwn::Binary
{


PE::PE(uptr Offset, usize Size)
{
    auto SpanView = std::span<u8> {(u8*)Offset, Size};
    if ( !ParsePeFromMemory(SpanView) )
    {
        throw std::runtime_error("PE initialization failed");
    }
}


PE::PE(std::filesystem::path const& Path)
{
    auto hFile = ValueOr(FileSystem::File::Open(Path.wstring(), L"r"), INVALID_HANDLE_VALUE);
    if ( hFile == INVALID_HANDLE_VALUE )
    {
        throw std::runtime_error("PE initialization failed");
    }

    auto PeFile     = FileSystem::File(std::move(hFile));
    const auto Size = ValueOr(PeFile.Size(), (usize)0);
    const auto hMap = Value(PeFile.Map(PAGE_READONLY));
    auto View       = Value(PeFile.View(hMap.get(), FILE_MAP_READ, 0, Size));

    auto SpanView = std::span<u8> {(u8*)View.get(), Size};
    if ( !ParsePeFromMemory(SpanView) )
    {
        throw std::runtime_error("PE initialization failed");
    }
}


bool
PE::ParsePeFromMemory(std::span<u8> const& MzView)
{
    //
    // Parse the DOS header
    //
    if ( MzView.size() < sizeof(IMAGE_DOS_HEADER) || *((u16*)&MzView[0]) != IMAGE_DOS_SIGNATURE )
    {
        return false;
    }

    m_DosBase = (uptr)MzView.data();
    ::memcpy(&m_DosHeader, MzView.data(), sizeof(IMAGE_DOS_HEADER));

    //
    // Parse the Rich headers
    //
    // TODO

    //
    // Parse the PE header
    //
    auto PeView = MzView.subspan(m_DosHeader.e_lfanew);
    if ( PeView.size() < MIN(sizeof(IMAGE_NT_HEADERS32), sizeof(IMAGE_NT_HEADERS64)) ||
         (*((u32*)&PeView[0]) != IMAGE_NT_SIGNATURE) )
    {
        return false;
    }

    try
    {
        const u16 MachineCode = *((u16*)&PeView[4]);
        m_Is64b               = [&MachineCode]()
        {
            switch ( MachineCode )
            {
            case IMAGE_FILE_MACHINE_ARM:
            case IMAGE_FILE_MACHINE_I386:
                return false;

            case IMAGE_FILE_MACHINE_AMD64:
            case IMAGE_FILE_MACHINE_ARM64:
                return true;
            };
            throw std::runtime_error("Unsupported architecture");
        }();
    }
    catch ( std::runtime_error const& e )
    {
        err(e.what());
        return false;
    }

    //
    // Copy the PE header, specialize the variant `m_PeHeader` from the header
    //
    {
        m_NtBase = (uptr)PeView.data();
        if ( !m_Is64b )
        {
            PeHeader32 pe {};
            if ( PeView.size() < sizeof(pe) )
                return false;

            ::memcpy(&pe, PeView.data(), sizeof(pe));
            m_PeHeader = std::move(pe);
        }
        else
        {
            PeHeader64 pe {};
            if ( PeView.size() < sizeof(pe) )
                return false;

            ::memcpy(&pe, PeView.data(), sizeof(pe));
            m_PeHeader = std::move(pe);
        }
    }

    m_PeMaxVa = (uptr)MzView.data() + MzView.size();

    //
    // Fill up sections and data directories
    //
    if ( !FillSections() || !FillDataDirectories() )
    {
        return false;
    }

    //
    // Populate all the other directories
    //

#define DoParse(x)                                                                                                     \
    {                                                                                                                  \
        if ( !Fill##x() )                                                                                              \
        {                                                                                                              \
            err("Failed parsing '" #x "' section.");                                                                   \
            return false;                                                                                              \
        }                                                                                                              \
    }

    DoParse(ExportTable);
    DoParse(ImportTable);
    DoParse(Resources);
    DoParse(Exception);
    DoParse(Security);
    DoParse(Relocations);
    DoParse(Architecture);
    DoParse(ThreadLocalStorage);
    DoParse(LoadConfiguration);
    DoParse(Debug);
    DoParse(GlobalPointer);
    DoParse(BoundImport);
    DoParse(ImportAddressTable);
    DoParse(DelayImport);
    DoParse(ComDescriptor);

#undef DoParse

    return true;
}


template<typename T>
bool
PE::IsWithinBounds(const T& Address) const
{
    const auto ptr  = (uptr*)(&Address);
    const auto addr = *ptr;
    return m_DosBase <= addr && addr < m_PeMaxVa;
}


PE::PeSectionHeader*
PE::FirstSection() const
{
    return m_Is64b ? (PE::PeSectionHeader*)IMAGE_FIRST_SECTION((PeHeader64*)Base()) :
                     (PE::PeSectionHeader*)IMAGE_FIRST_SECTION((PeHeader32*)Base());
}


#define GetField(Type, Field, Variant)                                                                                 \
    [this]()                                                                                                           \
    {                                                                                                                  \
        return std::visit(                                                                                             \
            overloaded {                                                                                               \
                [](Type##32 const& p)                                                                                  \
                {                                                                                                      \
                    return p.Field;                                                                                    \
                },                                                                                                     \
                [](Type##64 const& p)                                                                                  \
                {                                                                                                      \
                    return p.Field;                                                                                    \
                }},                                                                                                    \
            Variant);                                                                                                  \
    }()

#define GetPeField(Field) GetField(PeHeader, Field, Header())


bool
PE::FillSections()
{
    const u16 NumberOfSections = GetPeField(FileHeader.NumberOfSections);
    const u32 SymbolTable      = GetPeField(FileHeader.PointerToSymbolTable);
    const u32 NumberOfSymbols  = GetPeField(FileHeader.NumberOfSymbols);
    const auto SectionView     = std::span<PE::PeSectionHeader>(FirstSection(), (usize)NumberOfSections);

    std::for_each(
        SectionView.begin(),
        SectionView.end(),
        [this](auto const& Section)
        {
            this->m_PeSections.push_back(Section);
        });

    return true;
}


bool
PE::FillDataDirectories()
{
    const IMAGE_DATA_DIRECTORY* const DataDirectory = GetPeField(OptionalHeader.DataDirectory);
    auto const NumberOfRvaAndSizes =
        MIN(GetPeField(OptionalHeader.NumberOfRvaAndSizes), IMAGE_NUMBEROF_DIRECTORY_ENTRIES);

    for ( usize i = 0; i < NumberOfRvaAndSizes; i++ )
    {
        m_PeDataDirectories.emplace_back(DataDirectory[i]);
    }

    return true;
}


template<typename Pred>
Result<PE::PeSectionHeader>
PE::FindSection(Pred Condition)
{
    auto const& it = std::find_if(m_PeSections.cbegin(), m_PeSections.cend(), Condition);
    if ( it == m_PeSections.cend() )
    {
        return Err(ErrorCode::NotFound);
    }
    return Ok(*it);
}


Result<PE::PeSectionHeader>
PE::FindSectionFromRva(uptr Rva)
{
    auto Predicate = [&Rva](PE::PeSectionHeader const& s)
    {
        return (s.VirtualAddress <= Rva && Rva < s.VirtualAddress + s.Misc.VirtualSize);
    };

    return FindSection(Predicate);
}


uptr
PE::GetVirtualAddress(uptr Rva, u8 DirectoryIndex)
{
    if ( DirectoryIndex >= IMAGE_NUMBEROF_DIRECTORY_ENTRIES )
    {
        return 0;
    }
    auto res = FindSectionFromRva(m_PeDataDirectories[DirectoryIndex].VirtualAddress);
    if ( Failed(res) )
    {
        return 0;
    }
    auto const& Section = Value(res);
    const uptr ptr      = m_DosBase + Rva - static_cast<uptr>(Section.VirtualAddress - Section.PointerToRawData);
    return (m_DosBase <= ptr && ptr < m_PeMaxVa) ? ptr : 0;
}


bool
PE::FillExportTable()
{
    auto GetExportVa = [this](uptr Rva)
    {
        return GetVirtualAddress(Rva, IMAGE_DIRECTORY_ENTRY_EXPORT);
    };

    const auto& DirectoryExportEntry         = m_PeDataDirectories[IMAGE_DIRECTORY_ENTRY_EXPORT];
    const PeExportDirectory* ExportDirectory = (PeExportDirectory*)GetExportVa(DirectoryExportEntry.VirtualAddress);
    if ( !ExportDirectory )
    {
        return true;
    }

    ::memcpy(&m_PeExportDirectory, ExportDirectory, sizeof(PeExportDirectory));
    const auto ExportNameOrdinalTable = (u16*)GetExportVa(m_PeExportDirectory.Header.AddressOfNameOrdinals);
    const auto ExportFunctionTable    = (u32*)GetExportVa(m_PeExportDirectory.Header.AddressOfFunctions);
    const auto ExportNameTable        = (u32*)GetExportVa(m_PeExportDirectory.Header.AddressOfNames);

    for ( usize i = 0; i < ExportDirectory->NumberOfFunctions; i++ )
    {
        PeExportEntry entry {
            .Ordinal    = ExportNameOrdinalTable[i],
            .Rva        = ExportFunctionTable[i],
            .NameOffset = ExportNameTable[i],
        };
        const char* Name = (char*)GetExportVa(entry.NameOffset);
        if ( !Name )
        {
            return false;
        }
        entry.Name = std::string {Name, MIN(MAX_PATH, ::strlen(Name))};
        m_PeExportDirectory.Entries.push_back(std::move(entry));
    }

    return true;
}


template<typename T1, typename T2>
PE::PeImportDescriptor
PE::BuildImportEntry(const char* Name, const IMAGE_IMPORT_DESCRIPTOR* ImportDescriptor)
{
    auto GetImportVa = [this](uptr Rva)
    {
        return GetVirtualAddress(Rva, IMAGE_DIRECTORY_ENTRY_IMPORT);
    };

    PE::PeImportDescriptor Entry {};
    ::memcpy(&Entry, ImportDescriptor, sizeof(IMAGE_IMPORT_DESCRIPTOR));
    Entry.Name2 = std::string {Name, MIN(MAX_PATH, ::strlen(Name))};

    const T1* CurrentThunk = (T1*)GetImportVa(Entry.OriginalFirstThunk);

    while ( CurrentThunk->u1.AddressOfData )
    {
        T2 NewThunk {};
        ::memcpy(&NewThunk, CurrentThunk, sizeof(T1));

        if ( (std::is_same<T2, PeThunkData64>::value && !IMAGE_SNAP_BY_ORDINAL64(CurrentThunk->u1.Ordinal)) ||
             (std::is_same<T2, PeThunkData32>::value && !IMAGE_SNAP_BY_ORDINAL32(CurrentThunk->u1.Ordinal)) )
        {
            const PIMAGE_IMPORT_BY_NAME pfnName = (PIMAGE_IMPORT_BY_NAME)GetImportVa(CurrentThunk->u1.AddressOfData);
            NewThunk.Hint                       = pfnName->Hint;
            const char* FunctionName            = pfnName->Name;
            NewThunk.Name                       = std::string {FunctionName, MIN(MAX_PATH, ::strlen(FunctionName))};
        }

        Entry.Functions.push_back(std::move(NewThunk));
        CurrentThunk++;
    }
    return Entry;
}


bool
PE::FillImportTable()
{
    auto GetImportVa = [this](uptr Rva)
    {
        return GetVirtualAddress(Rva, IMAGE_DIRECTORY_ENTRY_IMPORT);
    };

    // TODO: add bound checks everywhere

    const IMAGE_IMPORT_DESCRIPTOR* ImportDescriptor =
        (IMAGE_IMPORT_DESCRIPTOR*)GetImportVa(m_PeDataDirectories[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
    if ( !ImportDescriptor )
    {
        return true;
    }

    if ( !IsWithinBounds(ImportDescriptor) )
    {
        return false;
    }

    while ( ImportDescriptor->Characteristics )
    {
        const char* Name = (char*)GetImportVa(ImportDescriptor->Name);
        if ( !Name )
        {
            return false;
        }

        PeImportDescriptor CurrentEntry =
            m_Is64b ? BuildImportEntry<IMAGE_THUNK_DATA64, PeThunkData64>(Name, ImportDescriptor) :
                      BuildImportEntry<IMAGE_THUNK_DATA32, PeThunkData32>(Name, ImportDescriptor);

        m_PeImportTable.Entries.push_back(std::move(CurrentEntry));
        ImportDescriptor++;
    }

    return true;
}


bool
PE::FillResources()
{
    auto GetResourceVa = [this](uptr Rva)
    {
        return GetVirtualAddress(Rva, IMAGE_DIRECTORY_ENTRY_RESOURCE);
    };

    const auto ResourceDirectory =
        (IMAGE_RESOURCE_DIRECTORY*)GetResourceVa(m_PeDataDirectories[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress);
    if ( !ResourceDirectory )
    {
        return true;
    }

    if ( !IsWithinBounds(ResourceDirectory) )
    {
        return false;
    }

    const usize NumberOfEntries = ResourceDirectory->NumberOfIdEntries + ResourceDirectory->NumberOfNamedEntries;
    ::memcpy(&m_PeResourceDirectory, ResourceDirectory, sizeof(IMAGE_RESOURCE_DIRECTORY));

    const auto ResourceTable = (PeResourceDirectoryEntry*)((uptr)ResourceDirectory + sizeof(IMAGE_RESOURCE_DIRECTORY));

    for ( usize ResourceIndex = 0; ResourceIndex < NumberOfEntries; ResourceIndex++ )
    {
        auto const& CurrentResource = ResourceTable[ResourceIndex];

        if ( (uptr)std::addressof(CurrentResource) >= m_PeMaxVa )
        {
            return false;
        }

        if ( CurrentResource.DataIsDirectory )
        {
        }
        else if ( CurrentResource.NameIsString )
        {
            const uptr ResourceNameLocation = (uptr)ResourceDirectory + CurrentResource.NameOffset;
            if ( !IsWithinBounds(ResourceNameLocation) || ResourceNameLocation < (uptr)ResourceDirectory )
            {
                return false;
            }

            const auto ResourceName = reinterpret_cast<PIMAGE_RESOURCE_DIR_STRING_U>(ResourceNameLocation);

            ResourceEntry Entry {
                .Type = PE::ResourceType::WideString,
                .Data = ResourceEntryWideString {ResourceName->NameString, MIN((usize)MAX_PATH, ResourceName->Length)}};

            m_PeResourceDirectory.Entries.push_back(std::move(Entry));
        }
        else // Raw
        {
        }
    }

    return true;
}


bool
PE::FillException()
{
    auto GetExceptionVa = [this](uptr Rva)
    {
        return GetVirtualAddress(Rva, IMAGE_DIRECTORY_ENTRY_EXCEPTION);
    };

    const auto ExceptionDirectory = (IMAGE_RUNTIME_FUNCTION_ENTRY*)GetExceptionVa(
        m_PeDataDirectories[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress);

    if ( !ExceptionDirectory )
    {
        return true;
    }

    const auto ExceptionDirectorySize = m_PeDataDirectories[IMAGE_DIRECTORY_ENTRY_EXCEPTION].Size;

    if ( !IsWithinBounds(ExceptionDirectory) || !IsWithinBounds(((uptr)ExceptionDirectory) + ExceptionDirectorySize) )
    {
        return false;
    }

    const auto NumberOfExceptionEntries = ExceptionDirectorySize / sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY);
    const auto ExceptionTable = std::span<IMAGE_RUNTIME_FUNCTION_ENTRY> {ExceptionDirectory, NumberOfExceptionEntries};

    bool bIsMalformed {false};

    std::for_each(
        ExceptionTable.begin(),
        ExceptionTable.end(),
        [this, &bIsMalformed, &GetExceptionVa](const IMAGE_RUNTIME_FUNCTION_ENTRY& e)
        {
            if ( bIsMalformed )
            {
                return;
            }

#if defined(_ARM_) || defined(_ARM64_)
            // TODO adjust from `Flags` field value, based on `ARM64_FNPDATA_FLAGS`
            DWORD EndAddress {e.BeginAddress + e.FunctionLength};
#else
            DWORD EndAddress {e.EndAddress};
#endif

            if ( e.BeginAddress > EndAddress )
            {
                bIsMalformed = true;
                return;
            }

            PeExceptionTableEntry entry {};
            ::memcpy(&entry, &e, sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY));
            entry.EndAddress = EndAddress;
            entry.Size       = EndAddress - e.BeginAddress;
            entry.UnwindRawBytes.reserve(entry.Size);

            Result<PE::PeSectionHeader> res = PE::FindSectionFromRva(entry.BeginAddress);
            if ( Failed(res) )
            {
                bIsMalformed = true;
                return;
            }

            auto const& section = Value(res);
            if ( section.Characteristics & IMAGE_SCN_CNT_CODE == 0 )
            {
                bIsMalformed = true;
                return;
            }

            const auto UnwindCodeAddress = (uptr)RtlOffsetToPointer(m_DosBase, entry.BeginAddress);
            entry.UnwindRawBytes.assign((u8*)UnwindCodeAddress, (u8*)UnwindCodeAddress + entry.Size);
            m_PeExceptionTable.Entries.push_back(std::move(entry));
        });

    return bIsMalformed == false;
}


bool
PE::FillSecurity()
{
    // TODO
    return true;
}


bool
PE::FillRelocations()
{
    auto GetRelocationVa = [this](uptr Rva)
    {
        return GetVirtualAddress(Rva, IMAGE_DIRECTORY_ENTRY_BASERELOC);
    };

    const auto RelocationDescriptorBase =
        (IMAGE_BASE_RELOCATION*)GetRelocationVa(m_PeDataDirectories[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
    if ( !RelocationDescriptorBase )
    {
        return true;
    }

    if ( !IsWithinBounds(RelocationDescriptorBase) )
    {
        return false;
    }

    const usize RelocationDescriptorSize = m_PeDataDirectories[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
    usize RelocationCurrentSize          = 0;

    auto CurrentRelocationDescriptor = RelocationDescriptorBase;
    while ( RelocationCurrentSize < RelocationDescriptorSize )
    {
        if ( !CurrentRelocationDescriptor || !CurrentRelocationDescriptor->VirtualAddress ||
             !CurrentRelocationDescriptor->SizeOfBlock )
        {
            break;
        }

        if ( !IsWithinBounds(CurrentRelocationDescriptor) ||
             CurrentRelocationDescriptor->SizeOfBlock < sizeof(IMAGE_BASE_RELOCATION) )
        {
            return false;
        }

        PeImageBaseRelocation Entry {};
        Entry.VirtualAddress = CurrentRelocationDescriptor->VirtualAddress;
        Entry.SizeOfBlock    = CurrentRelocationDescriptor->SizeOfBlock;
        Entry.NumberOfEntries =
            (CurrentRelocationDescriptor->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(u16);

        const auto RelocEntryView = std::span<u16>(
            (u16*)((uptr)CurrentRelocationDescriptor + sizeof(IMAGE_BASE_RELOCATION)),
            Entry.NumberOfEntries);
        if ( !IsWithinBounds(RelocEntryView.end()) )
        {
            return false;
        }

        for ( const u16 TypeOffset : RelocEntryView )
        {
            if ( Entry.Entries.size() > Entry.NumberOfEntries )
            {
                return false;
            }

            const u16 Type                  = (TypeOffset & 0xf000) >> 12;
            const u16 Offset                = (TypeOffset & 0x0fff);
            const std::string_view TypeName = [&Type]()
            {
                switch ( Type )
                {
                case IMAGE_REL_BASED_ABSOLUTE:
                    return "IMAGE_REL_BASED_ABSOLUTE"sv;
                case IMAGE_REL_BASED_HIGH:
                    return "IMAGE_REL_BASED_HIGH"sv;
                case IMAGE_REL_BASED_LOW:
                    return "IMAGE_REL_BASED_LOW"sv;
                case IMAGE_REL_BASED_HIGHLOW:
                    return "IMAGE_REL_BASED_HIGHLOW"sv;
                case IMAGE_REL_BASED_HIGHADJ:
                    return "IMAGE_REL_BASED_HIGHADJ"sv;
                case IMAGE_REL_BASED_MACHINE_SPECIFIC_5:
                    return "IMAGE_REL_BASED_MACHINE_SPECIFIC_5"sv;
                case IMAGE_REL_BASED_RESERVED:
                    return "IMAGE_REL_BASED_RESERVED"sv;
                case IMAGE_REL_BASED_MACHINE_SPECIFIC_7:
                    return "IMAGE_REL_BASED_MACHINE_SPECIFIC_7"sv;
                case IMAGE_REL_BASED_MACHINE_SPECIFIC_8:
                    return "IMAGE_REL_BASED_MACHINE_SPECIFIC_8"sv;
                case IMAGE_REL_BASED_MACHINE_SPECIFIC_9:
                    return "IMAGE_REL_BASED_MACHINE_SPECIFIC_9"sv;
                case IMAGE_REL_BASED_DIR64:
                    return "IMAGE_REL_BASED_DIR64"sv;
                }
                return ""sv;
            }();
            if ( TypeName.empty() )
            {
                return false;
            }

            Entry.Entries.emplace_back(
                PeImageBaseRelocation::RelocationEntry {Type, Entry.VirtualAddress + Offset, TypeName});
        }

        if ( Entry.Entries.size() > Entry.NumberOfEntries )
        {
            return false;
        }

        m_PeRelocations.push_back(std::move(Entry));

        RelocationCurrentSize += CurrentRelocationDescriptor->SizeOfBlock;

        CurrentRelocationDescriptor =
            (IMAGE_BASE_RELOCATION*)((uptr)CurrentRelocationDescriptor + CurrentRelocationDescriptor->SizeOfBlock);
    }

    if ( RelocationCurrentSize != RelocationDescriptorSize )
    {
        return false;
    }

    return true;
}


bool
PE::FillArchitecture()
{
    auto GetArchitectureVa = [this](uptr Rva)
    {
        return GetVirtualAddress(Rva, IMAGE_DIRECTORY_ENTRY_ARCHITECTURE);
    };

    const auto Architecture = (IMAGE_ARCHITECTURE_ENTRY*)GetArchitectureVa(
        m_PeDataDirectories[IMAGE_DIRECTORY_ENTRY_ARCHITECTURE].VirtualAddress);
    const auto ArchitectureSize = m_PeDataDirectories[IMAGE_DIRECTORY_ENTRY_ARCHITECTURE].Size;

    if ( Architecture == nullptr || ArchitectureSize == 0 )
    {
        return true;
    }

    if ( !IsWithinBounds(Architecture) )
    {
        return false;
    }

    ::memcpy(&m_PeArchitecture, Architecture, sizeof(IMAGE_ARCHITECTURE_ENTRY));

    return true;
}


bool
PE::FillThreadLocalStorage()
{
    // TODO
    return true;
}


bool
PE::FillLoadConfiguration()
{
    auto GetDebugVa = [this](uptr Rva)
    {
        return GetVirtualAddress(Rva, IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG);
    };

    const auto LoadConfigDirectory = GetDebugVa(m_PeDataDirectories[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].VirtualAddress);

    if ( !LoadConfigDirectory )
    {
        return true;
    }

    if ( !IsWithinBounds(LoadConfigDirectory) )
    {
        return false;
    }

    // Header
    {
        if ( m_Is64b )
            ::memcpy(
                &m_PeLoadConfigDirectory.Header,
                reinterpret_cast<PIMAGE_LOAD_CONFIG_DIRECTORY64>(LoadConfigDirectory),
                sizeof(IMAGE_LOAD_CONFIG_DIRECTORY64));
        else
            ::memcpy(
                &m_PeLoadConfigDirectory.Header,
                reinterpret_cast<PIMAGE_LOAD_CONFIG_DIRECTORY32>(LoadConfigDirectory),
                sizeof(IMAGE_LOAD_CONFIG_DIRECTORY32));
    }

    return true;
}


bool
PE::FillDebug()
{
    auto GetDebugVa = [this](uptr Rva)
    {
        return GetVirtualAddress(Rva, IMAGE_DIRECTORY_ENTRY_DEBUG);
    };

    const std::string_view TargetName = ".debug";
    auto DebugSectionRes              = FindSection(
        [&TargetName](PE::PeSectionHeader const& s)
        {
            const auto CurrentName = std::string_view((char*)s.Name, 8);
            return (CurrentName == TargetName);
        });

    const PIMAGE_DEBUG_DIRECTORY DebugDirectory = reinterpret_cast<PIMAGE_DEBUG_DIRECTORY>(
        GetDebugVa(m_PeDataDirectories[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress));
    if ( !DebugDirectory )
    {
        return true;
    }

    if ( !IsWithinBounds(DebugDirectory) )
    {
        return false;
    }

    const usize NumberOfEntries =
        m_PeDataDirectories[IMAGE_DIRECTORY_ENTRY_DEBUG].Size / static_cast<DWORD>(sizeof(IMAGE_DEBUG_DIRECTORY));

    const auto DebugDirectoryEntryView = std::span<IMAGE_DEBUG_DIRECTORY>(DebugDirectory, NumberOfEntries);

    for ( auto const& DebugEntryView : DebugDirectoryEntryView )
    {
        PeDebugEntry DebugEntry {};
        ::memcpy(&DebugEntry, &DebugEntryView, sizeof(IMAGE_DEBUG_DIRECTORY));
        DebugEntry.TypeName = [&DebugEntry]()
        {
            switch ( DebugEntry.Type )
            {
            //
            // Note: Those values are a mixed of SDK and PHNT
            //
            case IMAGE_DEBUG_TYPE_UNKNOWN:
                return "IMAGE_DEBUG_TYPE_UNKNOWN"sv;
            case IMAGE_DEBUG_TYPE_COFF:
                return "IMAGE_DEBUG_TYPE_COFF"sv;
            case IMAGE_DEBUG_TYPE_CODEVIEW:
                return "IMAGE_DEBUG_TYPE_CODEVIEW"sv;
            case IMAGE_DEBUG_TYPE_FPO:
                return "IMAGE_DEBUG_TYPE_FPO"sv;
            case IMAGE_DEBUG_TYPE_MISC:
                return "IMAGE_DEBUG_TYPE_MISC"sv;
            case IMAGE_DEBUG_TYPE_EXCEPTION:
                return "IMAGE_DEBUG_TYPE_EXCEPTION"sv;
            case IMAGE_DEBUG_TYPE_FIXUP:
                return "IMAGE_DEBUG_TYPE_FIXUP"sv;
            case IMAGE_DEBUG_TYPE_OMAP_TO_SRC:
                return "IMAGE_DEBUG_TYPE_OMAP_TO_SRC"sv;
            case IMAGE_DEBUG_TYPE_OMAP_FROM_SRC:
                return "IMAGE_DEBUG_TYPE_OMAP_FROM_SRC"sv;
            case IMAGE_DEBUG_TYPE_BORLAND:
                return "IMAGE_DEBUG_TYPE_BORLAND"sv;
            case IMAGE_DEBUG_TYPE_RESERVED10:
                return "IMAGE_DEBUG_TYPE_BBT"sv;
            case IMAGE_DEBUG_TYPE_CLSID:
                return "IMAGE_DEBUG_TYPE_CLSID"sv;
            case IMAGE_DEBUG_TYPE_VC_FEATURE:
                return "IMAGE_DEBUG_TYPE_VC_FEATURE"sv;
            case IMAGE_DEBUG_TYPE_POGO:
                return "IMAGE_DEBUG_TYPE_POGO"sv;
            case IMAGE_DEBUG_TYPE_ILTCG:
                return "IMAGE_DEBUG_TYPE_ILTCG"sv;
            case IMAGE_DEBUG_TYPE_MPX:
                return "IMAGE_DEBUG_TYPE_MPX"sv;
            case IMAGE_DEBUG_TYPE_REPRO:
                return "IMAGE_DEBUG_TYPE_REPRO"sv;
            case 17:
                return "IMAGE_DEBUG_TYPE_EMBEDDEDPORTABLEPDB"sv;
            case IMAGE_DEBUG_TYPE_SPGO:
                return "IMAGE_DEBUG_TYPE_SPGO"sv;
            case 19:
                return "IMAGE_DEBUG_TYPE_SHA256"sv;
            case IMAGE_DEBUG_TYPE_EX_DLLCHARACTERISTICS:
                return "IMAGE_DEBUG_TYPE_EX_DLLCHARACTERISTICS"sv;
            case 21:
                return "IMAGE_DEBUG_TYPE_PERFMAP"sv;
            }
            return ""sv;
        }();
        if ( DebugEntry.TypeName.empty() )
        {
            err("[pe::debug] Invalid reported type {}", DebugEntry.TypeName);
            return false;
        }

        //
        // Collect data
        //
        const u8* RawDataPtr  = (u8*)GetDebugVa(DebugEntry.AddressOfRawData);
        const u32 RawDataSize = DebugEntry.SizeOfData;
        if ( RawDataSize && (!RawDataPtr || !IsWithinBounds(RawDataPtr) || !IsWithinBounds(RawDataPtr + RawDataSize)) )
        {
            return false;
        }

        DebugEntry.RawData.resize(RawDataSize);
        const auto RawData = std::span<u8>((u8*)RawDataPtr, (usize)RawDataSize);
        DebugEntry.RawData.assign(RawData.begin(), RawData.end());

        //
        // Append entry
        //
        m_PeDebugTable.push_back(std::move(DebugEntry));
    }

    return true;
}


bool
PE::FillGlobalPointer()
{
    // TODO
    return true;
}


bool
PE::FillBoundImport()
{
    // TODO
    // IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT
    return true;
}


bool
PE::FillImportAddressTable()
{
    auto GetIatVa = [this](uptr Rva)
    {
        return GetVirtualAddress(Rva, IMAGE_DIRECTORY_ENTRY_IAT);
    };

    const auto IatBase = (uptr)GetIatVa(m_PeDataDirectories[IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress);


    // TODO
    return true;
}


template<typename T1, typename T2>
Result<PE::PeDelayLoadDescriptor>
PE::BuildDelayImportEntry(const IMAGE_DELAYLOAD_DESCRIPTOR* DelayImportDescriptor)
{
    auto GetDelayImportVa = [this](uptr Rva)
    {
        return GetVirtualAddress(Rva, IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT);
    };

    const char* DllName = (char*)GetDelayImportVa(DelayImportDescriptor->DllNameRVA);
    if ( !DllName )
    {
        return Err(ErrorCode::MalformedFile);
    }

    PE::PeDelayLoadDescriptor Entry {};
    ::memcpy(&Entry, DelayImportDescriptor, sizeof(DelayImportDescriptor));
    Entry.DllName = std::string {DllName, MIN(MAX_PATH, ::strlen(DllName))};

    T1* CurrentThunk = (T1*)GetDelayImportVa(DelayImportDescriptor->ImportNameTableRVA);
    while ( CurrentThunk->u1.AddressOfData )
    {
        T2 NewThunk {};
        ::memcpy(&NewThunk, CurrentThunk, sizeof(T1));

        if ( (std::is_same_v<T2, PeThunkData64> && !IMAGE_SNAP_BY_ORDINAL64(CurrentThunk->u1.Ordinal)) ||
             (std::is_same_v<T2, PeThunkData32> && !IMAGE_SNAP_BY_ORDINAL32(CurrentThunk->u1.Ordinal)) )
        {
            const PIMAGE_IMPORT_BY_NAME pfnName =
                (PIMAGE_IMPORT_BY_NAME)GetDelayImportVa(CurrentThunk->u1.AddressOfData);

            if ( !pfnName )
            {
                return Err(ErrorCode::MalformedFile);
            }

            NewThunk.Hint            = pfnName->Hint;
            const char* FunctionName = pfnName->Name;
            usize FunctionNameLength = MIN(MAX_PATH, ::strlen(FunctionName));
            NewThunk.Name            = std::string {FunctionName, FunctionNameLength};
        }

        Entry.Functions.push_back(std::move(NewThunk));
        CurrentThunk++;
    }

    return Ok(Entry);
}


bool
PE::FillDelayImport()
{
    auto GetDelayImportVa = [this](uptr Rva)
    {
        return GetVirtualAddress(Rva, IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT);
    };

    auto DelayLoadDescriptor = (const IMAGE_DELAYLOAD_DESCRIPTOR*)GetDelayImportVa(
        m_PeDataDirectories[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT].VirtualAddress);
    if ( !DelayLoadDescriptor )
    {
        return true;
    }

    if ( !IsWithinBounds(DelayLoadDescriptor) )
    {
        return false;
    }

    while ( DelayLoadDescriptor->DllNameRVA )
    {
        // TODO add bound checks
        auto res = m_Is64b ? BuildDelayImportEntry<IMAGE_THUNK_DATA64, PeThunkData64>(DelayLoadDescriptor) :
                             BuildDelayImportEntry<IMAGE_THUNK_DATA32, PeThunkData32>(DelayLoadDescriptor);
        if ( Failed(res) )
        {
            return false;
        }

        m_PeDelayImportTable.Entries.push_back(std::move(Value(res)));
        DelayLoadDescriptor++;
    }
    return true;
}


bool
PE::FillComDescriptor()
{
    auto GetComDescriptorVa = [this](uptr Rva)
    {
        return GetVirtualAddress(Rva, IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR);
    };

    const PeComDescriptor* ComHeader = reinterpret_cast<PeComDescriptor*>(
        GetComDescriptorVa(m_PeDataDirectories[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].VirtualAddress));
    if ( !ComHeader )
    {
        return true;
    }

    if ( ComHeader->cb != sizeof(IMAGE_COR20_HEADER) )
    {
        return false;
    }

    ::memcpy(&m_PeComDescriptor, ComHeader, sizeof(IMAGE_COR20_HEADER));

    //
    // Handle .NET metadata (super basic)
    //
    if ( m_PeComDescriptor.MetaData.VirtualAddress && m_PeComDescriptor.MetaData.Size )
    {
        const uptr MetadataBase = GetComDescriptorVa(m_PeComDescriptor.MetaData.VirtualAddress);
        if ( !MetadataBase )
            return false;

        auto& MetaData      = m_PeComDescriptor;
        uptr MetadataCursor = MetadataBase;

        ///
        ///@brief Read an arbitrary native type from the cursor and update it
        ///
        auto GetNext = [this, &MetaData, &MetadataCursor]<std::integral T>(T& out) -> bool
        {
            T* ptr = (T*)MetadataCursor;
            MetadataCursor += sizeof(T);
            if ( !IsWithinBounds(ptr) )
                return false;
            out = *ptr;
            return true;
        };

        ///
        ///@brief Read a null-terminated string
        ///
        auto GetNextString = [this, &MetaData, &MetadataCursor](std::string& out) -> bool
        {
            char* StartPointer {(char*)MetadataCursor};
            auto sz = ::strlen((char*)MetadataCursor);
            MetadataCursor += sz;
            if ( !IsWithinBounds(MetadataCursor) )
                return false;

            out.assign(StartPointer, sz);
            return true;
        };

        if ( !GetNext(MetaData.Signature) || !GetNext(MetaData.MajorVersion) || !GetNext(MetaData.MinorVersion) ||
             !GetNext(MetaData.Reserved) || !GetNext(MetaData.Length) || !GetNextString(MetaData.VersionString) ||
             !GetNext(MetaData.Flags) || !GetNext(MetaData.Streams) )
            return false;
    }

    return true;
}


} // namespace pwn::Binary
