#include "Win32/PE.hpp"

#include "Win32/FileSystem.hpp"

namespace pwn::Binary
{


PE::PE(uptr Offset, usize Size)
{
    auto SpanView = std::span<u8> {(u8*)Offset, Size};
    m_IsValid     = ParsePeFromMemory(SpanView);
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
    if ( View[0] != 'M' || View[1] != 'Z' )
    {
        return false;
    }

    ::memcpy(&m_DosHeader, View.data(), sizeof(DosHeader));

    //
    // Parse the Rich headers
    //
    // TODO

    //
    // Parse the PE header
    //
    auto PeView = View.subspan(m_DosHeader.e_lfanew);
    if ( PeView[0] != 'P' || PeView[1] != 'E' )
    {
        return false;
    }

    const u16 MachineCode = *((u16*)&PeView[2]);
    m_Is64b               = [&MachineCode]()
    {
        switch ( MachineCode )
        {
        case IMAGE_FILE_MACHINE_AMD64:
        case IMAGE_FILE_MACHINE_ARM64:
            return true;
        };
        return false;
    }();

    m_NtBase = (uptr)PeView.data();
    ::memcpy(&m_PeHeader, PeView.data(), sizeof(PeHeader));

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
    for ( bool res : {
              FillExportTable(),
              FillImportTable(),
              FillResources(),
              FillException(),
              FillSecurity(),
              FillRelocations(),
              FillArchitecture(),
              FillThreadLocalStorage(),
              FillLoadConfiguration(),
              FillDebug(),
              FillGlobalPointer(),
              FillBoundImport(),
              FillImportAddressTable(),
              FillDelayImport(),
              FillComDescriptor(),
          } )
    {
        if ( !res )
        {
            return false;
        }
    }

    return true;
}


PE::PeSectionHeader*
PE::FirstSection()
{
    return (PE::PeSectionHeader*)IMAGE_FIRST_SECTION((PE::PeHeader*)Base());
}


bool
PE::FillSections()
{
    const u16 NumberOfSections = FileHeader().NumberOfSections;
    const u32 SymbolTable      = FileHeader().PointerToSymbolTable;
    const u32 NumberOfSymbols  = FileHeader().NumberOfSymbols;
    auto SectionSpan           = std::span<PE::PeSectionHeader>(FirstSection(), (usize)NumberOfSections);

    for ( auto const& Section : SectionSpan )
    {
        m_PeSections.push_back(Section);
    }

    return true;
}


bool
PE::FillDataDirectories()
{
    auto DataDirectoryBase         = std::addressof(OptionalHeader().DataDirectory);
    const auto NumberOfRvaAndSizes = MIN(OptionalHeader().NumberOfRvaAndSizes, 16);

    for ( usize i = 1; i < NumberOfRvaAndSizes; i++ )
    {
        auto DataDirectory = DataDirectoryBase[i];
        m_PeDataDirectories.push_back(DataDirectory[i]);
    }

    return true;
}


std::optional<PE::PeSectionHeader>
PE::FindSectionFromRva(uptr Rva)
{
    auto const& it = std::find_if(
        m_PeSections.cbegin(),
        m_PeSections.cend(),
        [&Rva](PE::PeSectionHeader const& s)
        {
            return Rva <= s.VirtualAddress && s.VirtualAddress < s.Misc.VirtualSize;
        });

    if ( it == m_PeSections.cend() )
    {
        return std::nullopt;
    }

    return *it;
}


bool
PE::FillExportTable()
{
    const auto ExportDirectory =
        VA<IMAGE_EXPORT_DIRECTORY*>(m_PeDataDirectories[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
    ::memcpy(&m_PeExportDirectory, ExportDirectory, sizeof(PeExportDirectory));
    const auto ExportNameOrdinalTable = VA<u32*>(m_PeExportDirectory.AddressOfNameOrdinals);
    const auto ExportFunctionTable    = VA<u32*>(m_PeExportDirectory.AddressOfFunctions);
    const auto ExportNameTable        = VA<u16*>(m_PeExportDirectory.AddressOfNames);

    for ( usize i = 0; i < ExportDirectory->NumberOfFunctions; i++ )
    {
        PeExportEntry entry {};
        entry.Ordinal    = *(ExportNameOrdinalTable + i);
        entry.NameOffset = *(ExportNameTable + i);
        entry.Rva        = *(ExportFunctionTable + i);

        const char* Name = VA<char*>(entry.NameOffset);
        entry.Name       = std::string {Name, ::strlen(Name)};
        m_PeExportTable.push_back(std::move(entry));
    }

    return true;
}


bool
PE::FillImportTable()
{
    // TODO
    return true;
}


bool
PE::FillResources()
{
    // TODO
    return true;
}


bool
PE::FillException()
{
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
    // TODO
    return true;
}


bool
PE::FillArchitecture()
{
    const auto Architecture =
        VA<IMAGE_ARCHITECTURE_ENTRY*>(m_PeDataDirectories[IMAGE_DIRECTORY_ENTRY_ARCHITECTURE].VirtualAddress);

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
    // TODO
    return true;
}


bool
PE::FillDelayImport()
{
    // TODO
    return true;
}


bool
PE::FillComDescriptor()
{
    // TODO
    return true;
}


} // namespace Binary
