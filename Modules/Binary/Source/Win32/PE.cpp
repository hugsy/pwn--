#include "Win32/PE.hpp"

#include <memory>

#include "Win32/FileSystem.hpp"


namespace pwn::Binary
{


PE::PE(uptr Offset, usize Size)
{
    m_IsValid = ParsePeFromMemory(std::span<u8> {(u8*)Offset, Size});
}


PE::PE(std::filesystem::path const& Path)
{
    auto hFile = ValueOr(FileSystem::File::Open(Path.wstring(), L"r"), INVALID_HANDLE_VALUE);
    if ( hFile == INVALID_HANDLE_VALUE )
    {
        return;
    }

    auto PeFile     = FileSystem::File(std::move(hFile));
    const auto Size = ValueOr(PeFile.Size(), (usize)0);
    const auto hMap = FileSystem::FileMapViewHandle {Value(PeFile.Map(PAGE_READONLY))};
    auto View       = PeFile.View(hMap.get(), FILE_MAP_READ, 0, Size);
    if ( Failed(View) )
    {
        return;
    }

    auto SpanView = std::span<u8> {(u8*)Value(View), Size};
    m_IsValid     = ParsePeFromMemory(SpanView);
}


bool
PE::ParsePeFromMemory(std::span<u8> const& View)
{
    //
    // Parse the DOS header
    //
    if ( View.size() < sizeof(DosHeader) || View[0] != 'M' || View[1] != 'Z' )
    {
        return false;
    }

    m_DosBase = (uptr)View.data();
    ::memcpy(&m_DosHeader, View.data(), sizeof(DosHeader));

    //
    // Parse the Rich headers
    //
    // TODO

    //
    // Parse the PE header
    //
    auto PeView     = View.subspan(m_DosHeader.e_lfanew);
    const u32 Magic = *((u32*)&PeView[0]);
    if ( Magic != IMAGE_NT_SIGNATURE )
    {
        return false;
    }

    try
    {
        const u16 MachineCode = *((u16*)&PeView[4]);
        this->m_Is64b         = [&MachineCode]()
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

    m_PeMaxVa = (uptr)View.data() + View.size();

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
    // DoParse(ThreadLocalStorage);
    // DoParse(LoadConfiguration);
    // DoParse(Debug);
    // DoParse(GlobalPointer);
    // DoParse(BoundImport);
    DoParse(ImportAddressTable);
    DoParse(DelayImport);
    DoParse(ComDescriptor);

#undef DoParse

    return true;
}


template<typename T>
bool
PE::IsWithinBounds(const T& Address)
{
    auto ptr  = (uptr*)(&Address);
    auto addr = *ptr;
    return m_DosBase <= addr && addr < m_PeMaxVa;
}


PE::PeSectionHeader*
PE::FirstSection()
{
    return m_Is64b ? (PE::PeSectionHeader*)IMAGE_FIRST_SECTION((PeHeader64*)Base()) :
                     (PE::PeSectionHeader*)IMAGE_FIRST_SECTION((PeHeader32*)Base());
}


#define GetPeField(Field)                                                                                              \
    [this]()                                                                                                           \
    {                                                                                                                  \
        return std::visit(                                                                                             \
            overloaded {                                                                                               \
                [](PeHeader32 const& p)                                                                                \
                {                                                                                                      \
                    return p.Field;                                                                                    \
                },                                                                                                     \
                [](PeHeader64 const& p)                                                                                \
                {                                                                                                      \
                    return p.Field;                                                                                    \
                }},                                                                                                    \
            Header());                                                                                                 \
    }()


bool
PE::FillSections()
{
    const u16 NumberOfSections = GetPeField(FileHeader.NumberOfSections);
    const u32 SymbolTable      = GetPeField(FileHeader.PointerToSymbolTable);
    const u32 NumberOfSymbols  = GetPeField(FileHeader.NumberOfSymbols);
    auto SectionView           = std::span<PE::PeSectionHeader>(FirstSection(), (usize)NumberOfSections);

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


Result<PE::PeSectionHeader>
PE::FindSectionFromRva(uptr Rva)
{
    auto const& it = std::find_if(
        m_PeSections.cbegin(),
        m_PeSections.cend(),
        [&Rva](PE::PeSectionHeader const& s)
        {
            return (s.VirtualAddress <= Rva && Rva < s.VirtualAddress + s.Misc.VirtualSize);
        });

    if ( it == m_PeSections.cend() )
    {
        return Err(ErrorCode::NotFound);
    }

    return *it;
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
        return false;
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
    if ( !ImportDescriptor || !IsWithinBounds(ImportDescriptor) )
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

            if ( e.BeginAddress > e.EndAddress )
            {
                bIsMalformed = true;
                return;
            }

            PeExceptionTableEntry entry {};
            ::memcpy(&entry, &e, sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY));
            entry.Size = e.EndAddress - e.BeginAddress;
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

    const auto RelocationBase =
        (IMAGE_BASE_RELOCATION*)GetRelocationVa(m_PeDataDirectories[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);

    auto CurrentRelocation = RelocationBase;
    while ( true )
    {
        if ( !CurrentRelocation || !CurrentRelocation->VirtualAddress || !CurrentRelocation->SizeOfBlock )
        {
            break;
        }

        if ( !IsWithinBounds(CurrentRelocation) || CurrentRelocation->SizeOfBlock < sizeof(IMAGE_BASE_RELOCATION) )
        {
            return false;
        }

        PeImageBaseRelocation Entry {};
        Entry.VirtualAddress  = CurrentRelocation->VirtualAddress;
        Entry.SizeOfBlock     = CurrentRelocation->SizeOfBlock;
        Entry.NumberOfEntries = (CurrentRelocation->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(u16);

        auto res = FindSectionFromRva(Entry.VirtualAddress);
        if ( Failed(res) )
        {
            return false;
        }

        auto const& Section = Value(res);
        u16* RelocEntryAddr = (u16*)(m_DosBase + Entry.VirtualAddress);

        for ( usize i = 0; i < Entry.NumberOfEntries; i++, RelocEntryAddr++ )
        {
            const u16 Type                  = (*RelocEntryAddr & 0xf000) >> 12;
            const u16 Offset                = (*RelocEntryAddr & 0x0fff);
            const std::string_view TypeName = [&Type]()
            {
                switch ( Type )
                {
                case IMAGE_REL_BASED_ABSOLUTE:
                    return "IMAGE_REL_BASED_ABSOLUTE";
                case IMAGE_REL_BASED_HIGH:
                    return "IMAGE_REL_BASED_HIGH";
                case IMAGE_REL_BASED_LOW:
                    return "IMAGE_REL_BASED_LOW";
                case IMAGE_REL_BASED_HIGHLOW:
                    return "IMAGE_REL_BASED_HIGHLOW";
                case IMAGE_REL_BASED_HIGHADJ:
                    return "IMAGE_REL_BASED_HIGHADJ";
                case IMAGE_REL_BASED_MACHINE_SPECIFIC_5:
                    return "IMAGE_REL_BASED_MACHINE_SPECIFIC_5";
                case IMAGE_REL_BASED_RESERVED:
                    return "IMAGE_REL_BASED_RESERVED";
                case IMAGE_REL_BASED_MACHINE_SPECIFIC_7:
                    return "IMAGE_REL_BASED_MACHINE_SPECIFIC_7";
                case IMAGE_REL_BASED_MACHINE_SPECIFIC_8:
                    return "IMAGE_REL_BASED_MACHINE_SPECIFIC_8";
                case IMAGE_REL_BASED_MACHINE_SPECIFIC_9:
                    return "IMAGE_REL_BASED_MACHINE_SPECIFIC_9";
                case IMAGE_REL_BASED_DIR64:
                    return "IMAGE_REL_BASED_DIR64";
                default:
                    return "";
                }
            }();
            if ( TypeName.empty() )
            {
                return false;
            }

            Entry.Entries.emplace_back(
                PeImageBaseRelocation::RelocationEntry {Type, Entry.VirtualAddress + Offset, TypeName});
        }

        m_PeRelocations.push_back(std::move(Entry));

        CurrentRelocation = (IMAGE_BASE_RELOCATION*)((uptr)CurrentRelocation + CurrentRelocation->SizeOfBlock);
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

    ::memcpy(&m_PeArchitecture, Architecture, sizeof(PeArchitecture));

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
    // TODO
    return true;
}


bool
PE::FillDebug()
{
    // TODO
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

        if ( (std::is_same<T2, PeThunkData64>::value && !IMAGE_SNAP_BY_ORDINAL64(CurrentThunk->u1.Ordinal)) ||
             (std::is_same<T2, PeThunkData32>::value && !IMAGE_SNAP_BY_ORDINAL32(CurrentThunk->u1.Ordinal)) )
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
    // TODO
    return true;
}


} // namespace pwn::Binary
