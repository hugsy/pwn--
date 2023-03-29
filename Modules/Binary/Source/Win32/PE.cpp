#include "Win32/PE.hpp"

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
    if ( View[0] != 'M' || View[1] != 'Z' || View.size() < sizeof(DosHeader) )
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

    const u16 MachineCode         = *((u16*)&PeView[4]);
    const bool IsMachineSupported = [&MachineCode, this]()
    {
        switch ( MachineCode )
        {
        case IMAGE_FILE_MACHINE_ARM:
        case IMAGE_FILE_MACHINE_I386:
            this->m_Is64b = false;
            return true;

        case IMAGE_FILE_MACHINE_AMD64:
        case IMAGE_FILE_MACHINE_ARM64:
            this->m_Is64b = true;
            return true;
        };
        return false;
    }();
    if ( !IsMachineSupported )
    {
        return false;
    }

    // Copy the PE header, specialize the variant `m_PeHeader`
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
            return false;                                                                                              \
    }

    DoParse(ExportTable);
    DoParse(ImportTable);
    DoParse(Resources);
    // DoParse(Exception);
    // DoParse(Security);
    // DoParse(Relocations);
    DoParse(Architecture);
    // DoParse(ThreadLocalStorage);
    // DoParse(LoadConfiguration);
    // DoParse(Debug);
    // DoParse(GlobalPointer);
    // DoParse(BoundImport);
    DoParse(ImportAddressTable);
    DoParse(DelayImport);
    // DoParse(ComDescriptor);

#undef DoParse

    return true;
}


PE::PeSectionHeader*
PE::FirstSection()
{
    return m_Is64b ? (PE::PeSectionHeader*)IMAGE_FIRST_SECTION((PeHeader64*)Base()) :
                     (PE::PeSectionHeader*)IMAGE_FIRST_SECTION((PeHeader32*)Base());
}


#define GetPeField(F)                                                                                                  \
    [this]()                                                                                                           \
    {                                                                                                                  \
        return std::visit(                                                                                             \
            overloaded {                                                                                               \
                [](PeHeader32 const& p)                                                                                \
                {                                                                                                      \
                    return p.F;                                                                                        \
                },                                                                                                     \
                [](PeHeader64 const& p)                                                                                \
                {                                                                                                      \
                    return p.F;                                                                                        \
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

    for ( auto const& Section : SectionView )
    {
        m_PeSections.push_back(Section);
    }

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
        const IMAGE_DATA_DIRECTORY DataDirectoryEntry = DataDirectory[i];
        // TODO: add boundary check
        m_PeDataDirectories.push_back(std::move(DataDirectoryEntry));
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
        return 0;
    auto res = FindSectionFromRva(m_PeDataDirectories[DirectoryIndex].VirtualAddress);
    if ( Failed(res) )
        return 0;
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
        return false;

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
            return false;
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
            usize FunctionNameLength            = MIN(MAX_PATH, ::strlen(FunctionName));
            NewThunk.Name                       = std::string {FunctionName, FunctionNameLength};
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
        return false;

    while ( ImportDescriptor->Characteristics )
    {
        const char* Name = (char*)GetImportVa(ImportDescriptor->Name);
        if ( !Name )
            return false;

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
        return false;

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

    // TODO
    return true;
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

    // TODO
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
PE::PeDelayLoadDescriptor
PE::BuildDelayImportEntry(const char* DllName, const IMAGE_DELAYLOAD_DESCRIPTOR* DelayImportDescriptor)
{
    auto GetDelayImportVa = [this](uptr Rva)
    {
        return GetVirtualAddress(Rva, IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT);
    };

    PE::PeDelayLoadDescriptor Entry {};
    ::memcpy(&Entry, DelayImportDescriptor, sizeof(DelayImportDescriptor));
    Entry.DllName = std::string {DllName, MIN(MAX_PATH, ::strlen(DllName))};

    const T1* CurrentThunk = (T1*)GetDelayImportVa(Entry.ImportNameTableRVA);

    while ( CurrentThunk->u1.AddressOfData )
    {
        T2 NewThunk {};
        ::memcpy(&NewThunk, CurrentThunk, sizeof(T1));

        if ( (std::is_same<T2, PeThunkData64>::value && !IMAGE_SNAP_BY_ORDINAL64(CurrentThunk->u1.Ordinal)) ||
             (std::is_same<T2, PeThunkData32>::value && !IMAGE_SNAP_BY_ORDINAL32(CurrentThunk->u1.Ordinal)) )
        {
            const PIMAGE_IMPORT_BY_NAME pfnName =
                (PIMAGE_IMPORT_BY_NAME)GetDelayImportVa(CurrentThunk->u1.AddressOfData);
            NewThunk.Hint            = pfnName->Hint;
            const char* FunctionName = pfnName->Name;
            usize FunctionNameLength = MIN(MAX_PATH, ::strlen(FunctionName));
            NewThunk.Name            = std::string {FunctionName, FunctionNameLength};
        }

        Entry.Functions.push_back(std::move(NewThunk));
        CurrentThunk++;
    }
    return Entry;
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
        return false;

    while ( DelayLoadDescriptor->DllNameRVA )
    {
        const char* DllName = (char*)GetDelayImportVa(DelayLoadDescriptor->DllNameRVA);
        if ( !DllName )
            return false;

        PeDelayLoadDescriptor CurrentEntry =
            m_Is64b ? BuildDelayImportEntry<IMAGE_THUNK_DATA64, PeThunkData64>(DllName, DelayLoadDescriptor) :
                      BuildDelayImportEntry<IMAGE_THUNK_DATA32, PeThunkData32>(DllName, DelayLoadDescriptor);

        m_PeDelayImportTable.Entries.push_back(std::move(CurrentEntry));
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
