#include "win32/symbols.hpp"

#include "handle.hpp"
#include "log.hpp"
#include "win32/network.hpp"

static HANDLE __hProcess                        = nullptr;
static HMODULE __hModule                        = nullptr;
static std::optional<std::wstring> __SymbolPath = std::nullopt;
static pwn::SharedHandle __spProcess            = nullptr;


#pragma region Declaration
struct SYMBOL_INFOW
{
    ULONG SizeOfStruct;
    ULONG TypeIndex; // Type Index of symbol
    ULONG64 Reserved[2];
    ULONG Index;
    ULONG Size;
    ULONG64 ModBase; // Base Address of module comtaining this symbol
    ULONG Flags;
    ULONG64 Value;   // Value of symbol, ValuePresent should be 1
    ULONG64 Address; // Address of symbol including base address of module
    ULONG Register;  // register holding value or pointer to value
    ULONG Scope;     // scope of the symbol
    ULONG Tag;       // pdb classification
    ULONG NameLen;   // Actual length of name
    ULONG MaxNameLen;
    WCHAR Name[1]; // Name of symbol
};


typedef DWORD (*SymSetOptions_t)(DWORD SymOptions);
static SymSetOptions_t SymSetOptions = nullptr;

typedef BOOL (*SymInitializeW_t)(HANDLE hProcess, PWSTR UserSearchPath, BOOL fInvadeProcess);
static SymInitializeW_t SymInitializeW = nullptr;

typedef BOOL (*SymEnumerateModulesW64_t)(HANDLE hProcess, PVOID EnumModulesCallback, PVOID UserContext);
static SymEnumerateModulesW64_t SymEnumerateModulesW64 = nullptr;

typedef ULONG_PTR (*SymLoadModuleExW_t)(
    HANDLE hProcess,
    HANDLE hFile,
    PCWSTR ImageName,
    PCWSTR ModuleName,
    DWORD64 BaseOfDll,
    DWORD DllSize,
    PVOID ModLoadData,
    DWORD Flags);
static SymLoadModuleExW_t SymLoadModuleExW = nullptr;

typedef BOOL (
    *SymEnumSymbolsW_t)(HANDLE hProcess, ULONG64 BaseOfDll, PCWSTR Mask, PVOID EnumSymbolsCallback, PVOID UserContext);
static SymEnumSymbolsW_t SymEnumSymbolsW = nullptr;

typedef BOOL (*SymFromNameW_t)(HANDLE hProcess, PCWSTR Name, SYMBOL_INFOW* Symbol);
static SymFromNameW_t SymFromNameW = nullptr;

typedef BOOL (*SymFromAddrW_t)(HANDLE hProcess, uptr Address, uptr* Displacement, SYMBOL_INFOW* Symbol);
static SymFromAddrW_t SymFromAddrW = nullptr;

typedef BOOL (*SymSetSearchPathW_t)(HANDLE hProcess, PCTSTR SearchPath);
static SymSetSearchPathW_t SymSetSearchPathW = nullptr;

#ifndef SYMOPT_CASE_INSENSITIVE
#define SYMOPT_CASE_INSENSITIVE 0x00000001
#endif // SYMOPT_CASE_INSENSITIVE

#ifndef SYMOPT_UNDNAME
#define SYMOPT_UNDNAME 0x00000002
#endif // SYMOPT_UNDNAME

#ifndef SYMOPT_DEFERRED_LOADS
#define SYMOPT_DEFERRED_LOADS 0x00000004
#endif // SYMOPT_DEFERRED_LOADS

#ifndef MAX_SYM_NAME
#define MAX_SYM_NAME 2000
#endif // MAX_SYM_NAME

#pragma endregion Declaration


namespace pwn::windows::symbols
{

#pragma region Helpers

SymbolInfo
CreateSymbolInfo(SYMBOL_INFOW const* _si)
{
    SymbolInfo si {};
    si.Type     = _si->TypeIndex;
    si.Size     = _si->Size;
    si.ModBase  = _si->ModBase;
    si.Flags    = _si->Flags;
    si.Value    = _si->Value;
    si.Address  = _si->Address;
    si.Register = _si->Register;
    si.Name     = _si->Name;
    return si;
}

inline HANDLE
GetHandle()
{
    if ( !__hModule )
    {
        __hModule = LoadLibraryW(L"DbgHelp.dll");
        if ( __hModule && !__hProcess )
        {
            // Initialize the function pointers
            {
                SymSetOptions  = (SymSetOptions_t)::GetProcAddress(__hModule, "SymSetOptions");
                SymInitializeW = (SymInitializeW_t)::GetProcAddress(__hModule, "SymInitializeW");
                SymEnumerateModulesW64 =
                    (SymEnumerateModulesW64_t)::GetProcAddress(__hModule, "SymEnumerateModulesW64");
                SymLoadModuleExW  = (SymLoadModuleExW_t)::GetProcAddress(__hModule, "SymLoadModuleExW");
                SymEnumSymbolsW   = (SymEnumSymbolsW_t)::GetProcAddress(__hModule, "SymEnumSymbolsW");
                SymFromNameW      = (SymFromNameW_t)::GetProcAddress(__hModule, "SymFromNameW");
                SymFromAddrW      = (SymFromAddrW_t)::GetProcAddress(__hModule, "SymFromAddrW");
                SymSetSearchPathW = (SymSetSearchPathW_t)::GetProcAddress(__hModule, "SymSetSearchPathW");
            }

            // Initialize the debug engine for the target process
            {
                SymSetOptions(SYMOPT_UNDNAME | SYMOPT_DEFERRED_LOADS);

                __hProcess = ::GetCurrentProcess(); // TODO: adjust

                if ( SymInitializeW(__hProcess, nullptr, true) == FALSE )
                {
                    log::perror(L"SymInitialize()");
                    return nullptr;
                }

                if ( __SymbolPath )
                {
                    if ( Failed(Symbols::SetSymbolPath(__SymbolPath.value())) )
                    {
                        return nullptr;
                    }
                }
            }
        }
    }
    return __hProcess;
}

bool
EnumerateModulesW64Cb(PCWSTR ModuleName, uptr BaseOfDll, std::vector<std::tuple<uptr, std::wstring>>* Modules)
{
    Modules->push_back({(uptr)BaseOfDll, std::wstring {ModuleName}});
    return true;
};

#pragma pack(push, 1)
struct DebugInfoSection
{
    u32 Magic;
    GUID Guid;
    u32 Age;
    u8 Path[];
};
#pragma pack(pop)

///
///@brief Get a pointer to the Debug directory of the given module (if found)
///
///@param ModuleImageBase the base address of the module
///@return DebugInfoSection*
///
DebugInfoSection*
GetModuleDebugInfo(uptr const ModuleImageBase)
{
    const auto pDosHeader = (PIMAGE_DOS_HEADER)ModuleImageBase;
    if ( *((u16*)pDosHeader) != 'ZM' )
    {
        return nullptr;
    }

    const auto pNtHeader = (PIMAGE_NT_HEADERS)(ModuleImageBase + pDosHeader->e_lfanew);
    if ( *((u16*)pNtHeader) != 'EP' )
    {
        return nullptr;
    }

    const auto pDebugDirectory =
        (PIMAGE_DEBUG_DIRECTORY)(pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress + ModuleImageBase);
    if ( pDebugDirectory->Type != IMAGE_DEBUG_TYPE_CODEVIEW )
    {
        return nullptr;
    }

    DebugInfoSection* dbg = (DebugInfoSection*)(ModuleImageBase + pDebugDirectory->AddressOfRawData);
    if ( dbg->Magic != 'SDSR' )
    {
        return nullptr;
    }

    return dbg;
}

#pragma endregion

#pragma region Symbol class

Result<std::vector<std::tuple<uptr, std::wstring>>>
Symbols::EnumerateModules()
{
    HANDLE hProcess = GetHandle();
    if ( !hProcess )
    {
        return Err(ErrorCode::NotInitialized);
    }

    std::vector<std::tuple<uptr, std::wstring>> Modules;
    if ( SymEnumerateModulesW64(hProcess, &EnumerateModulesW64Cb, &Modules) == FALSE )
    {
        log::perror(L"SymEnumerateModulesW64()");
        return Err(ErrorCode::ExternalApiCallFailed);
    }

    return Ok(Modules);
}


bool
EnumSymProcCb(SYMBOL_INFOW* pSymInfo, ULONG SymbolSize, std::vector<SymbolInfo>* ModuleSymbolInfo)
{
    ModuleSymbolInfo->push_back(std::move(CreateSymbolInfo(pSymInfo)));
    return true;
};


Result<std::vector<SymbolInfo>>
Symbols::EnumerateFromModule(std::wstring_view const& ModuleName, std::wstring_view const& Mask)
{
    HANDLE hProcess = GetHandle();
    if ( !hProcess )
    {
        return Err(ErrorCode::NotInitialized);
    }

    u64 BaseOfDll = SymLoadModuleExW(hProcess, nullptr, ModuleName.data(), nullptr, 0, 0, nullptr, 0);
    if ( !BaseOfDll )
    {
        log::perror(L"SymLoadModuleExW()");
        return Err(ErrorCode::ExternalApiCallFailed);
    }

    std::vector<SymbolInfo> ModuleSymbolInfo;
    if ( ::SymEnumSymbolsW(hProcess, BaseOfDll, Mask.data(), &EnumSymProcCb, &ModuleSymbolInfo) == FALSE )
    {
        log::perror(L"SymEnumSymbolsW()");
        return Err(ErrorCode::ExternalApiCallFailed);
    }

    return Ok(ModuleSymbolInfo);
}


Result<uptr>
Symbols::ResolveFromName(std::wstring_view const& SymbolName)
{
    HANDLE hProcess = GetHandle();
    if ( !hProcess )
    {
        return Err(ErrorCode::NotInitialized);
    }

    auto pBuffer          = std::make_unique<u8[]>(sizeof(SYMBOL_INFOW) + MAX_SYM_NAME * sizeof(u16));
    auto pSymbol          = reinterpret_cast<SYMBOL_INFOW*>(pBuffer.get());
    pSymbol->SizeOfStruct = sizeof(SYMBOL_INFOW);
    pSymbol->MaxNameLen   = MAX_SYM_NAME;

    if ( ::SymFromNameW(hProcess, SymbolName.data(), pSymbol) == FALSE )
    {
        log::perror(L"SymFromNameW()");
        return Err(ErrorCode::ExternalApiCallFailed);
    }

    return Ok(pSymbol->Address);
}


Result<std::wstring>
Symbols::ResolveFromAddress(const uptr TargetAddress)
{
    HANDLE hProcess = GetHandle();
    if ( !hProcess )
    {
        return Err(ErrorCode::NotInitialized);
    }

    auto pBuffer          = std::make_unique<u8[]>(sizeof(SYMBOL_INFOW) + MAX_SYM_NAME * sizeof(u16));
    auto pSymbol          = reinterpret_cast<SYMBOL_INFOW*>(pBuffer.get());
    pSymbol->SizeOfStruct = sizeof(SYMBOL_INFOW);
    pSymbol->MaxNameLen   = MAX_SYM_NAME;

    if ( ::SymFromAddrW(hProcess, TargetAddress, nullptr, pSymbol) == FALSE )
    {
        log::perror(L"SymFromAddrW()");
        return Err(ErrorCode::ExternalApiCallFailed);
    }

    return Ok(std::wstring {pSymbol->Name});
}

Result<bool>
Symbols::SetSymbolPath(std::wstring_view const& NewSymbolPath)
{
    __SymbolPath = NewSymbolPath;
    if ( !__hProcess )
    {
        return Err(ErrorCode::InitializationFailed);
    }

    PCWSTR SymPath = __SymbolPath.has_value() ? __SymbolPath.value().c_str() : nullptr;
    if ( !SymPath )
    {
        return Ok(false);
    }

    if ( SymSetSearchPathW(__hProcess, SymPath) == FALSE )
    {
        log::perror(L"SymSetSearchPath()");
        return Err(ErrorCode::ExternalApiCallFailed);
    }

    return Ok(true);
}


Result<std::filesystem::path>
Symbols::DownloadModulePdbToDisk(std::string_view const& ModuleNameWithExt)
{
    //
    // Load the module as data
    //
    const std::string_view ModuleName = ModuleNameWithExt.substr(0, ModuleNameWithExt.size() - 4);
    UniqueLibraryHandle hMod {::LoadLibraryExA(ModuleNameWithExt.data(), nullptr, LOAD_LIBRARY_AS_DATAFILE)};
    if ( !hMod )
    {
        return Err(ErrorCode::ExternalApiCallFailed);
    }

    DebugInfoSection* dbg = GetModuleDebugInfo((uptr)(hMod.get()) & ~0x0f);
    if ( !dbg )
    {
        return Err(ErrorCode::GenericError);
    }

    //
    // Build the URL following the PDB URL format
    //
    std::stringstream url;
    const auto ModulePathWithPdb =
        std::filesystem::temp_directory_path() / std::filesystem::path(std::string(ModuleName) + ".pdb");
    {
        const auto ModuleNameWithPdb = ModulePathWithPdb.filename();
        url << "https://msdl.microsoft.com/download/symbols/" << ModuleNameWithPdb.string() << "/";
        url << std::setfill('0') << std::setw(8) << std::hex << dbg->Guid.Data1 << std::setw(4) << std::hex
            << dbg->Guid.Data2 << std::setw(4) << std::hex << dbg->Guid.Data3;
        for ( const u8 i : dbg->Guid.Data4 )
        {
            url << std::setw(2) << std::hex << (int)i;
        }
        url << dbg->Age << "/" << ModuleNameWithPdb.string();
    }

    //
    // Download the file
    //
    auto dlRes = pwn::windows::network::HTTP::DownloadFile(url.str(), ModulePathWithPdb);
    if ( Failed(dlRes) )
    {
        return Err(Error(dlRes).code);
    }

    return Ok(ModulePathWithPdb);
}


Result<std::vector<u8>>
Symbols::DownloadModulePdbToMemory(std::string_view const& ModuleNameWithExt)
{
    //
    // Download PDB
    //
    auto dlRes = Symbols::DownloadModulePdbToDisk(ModuleNameWithExt);
    if ( Failed(dlRes) )
    {
        return Err(Error(dlRes).code);
    }

    std::filesystem::path const& ModulePathWithPdb = Value(dlRes);
    u64 const RawPdbFileSize                       = std::filesystem::file_size(ModulePathWithPdb);
    std::vector<u8> RawPdb(RawPdbFileSize);

    //
    // Load file to memory
    //
    {
        UniqueHandle h(::CreateFileW(
            ModulePathWithPdb.c_str(),
            GENERIC_READ,
            FILE_SHARE_READ,
            nullptr,
            OPEN_EXISTING,
            0,
            nullptr));
        if ( !h )
        {
            return Err(ErrorCode::ExternalApiCallFailed);
        }

        if ( ::ReadFile(h.get(), RawPdb.data(), RawPdbFileSize, nullptr, nullptr) == FALSE )
        {
            return Err(ErrorCode::ExternalApiCallFailed);
        }
    }

    std::filesystem::remove(ModulePathWithPdb);
    return Ok(RawPdb);
}

#pragma endregion

#pragma region PDB7 class

/*
PDB7::PDB7()
{
}


PDB7::PDB7(std::wstring_view const& pdb_path)
{
    std::ifstream is(pdb_path, std::ios::binary | std::ios::ate);
    size_t len = is.tellg();
    pdbBuffer  = new char[len + 1];
    memset(pdbBuffer, 0, len + 1);
    is.seekg(0);
    is.read(pdbBuffer, len);
    is.close();

    this->pPDBHeader = (PDBHeader7*)this->pdbBuffer;


    struct RootPageNumList
    {
        int nums[];
    };

    RootPageNumList* list = (decltype(list))GetPage(this->pPDBHeader->root_stream_page_number_list_number);
    pRootStream           = (RootStream7*)GetPage(list->nums[0]);

    int* streamSizes = new int[pRootStream->num_streams];
    memset(streamSizes, 0, pRootStream->num_streams);

    int curPageNum = 0;

    for ( int i = 0; i < pRootStream->num_streams; i++ )
    {
        auto curSize   = pRootStream->stream_sizes[i];
        streamSizes[i] = curSize != 0xFFFFFFFF ? curSize : 0;

        // Log( "Stream %d size: %X", i, streamSizes[ i ] );
        auto neededPages = this->GetPageCount(streamSizes[i]);
        // Log( "Need %d pages", neededPages );

        std::vector<int>* nums = new std::vector<int>();

        for ( int x = 0; x < neededPages; x++ )
        {
            auto curNum = pRootStream->stream_sizes[pRootStream->num_streams + curPageNum++];
            // Log( "Page number for Stream %d: %x", i, curNum );
            nums->push_back(curNum);
        }

        streams.insert({i, nums});
    }

    pDBIHeader    = (DBIHeader*)GetStreamLoc(DBIStream);
    pSymbolStream = ReadStream(pDBIHeader->symbolStreamIndex);
}


char*
PDB7::GetPage(int index)
{
    return pdbBuffer + (index * this->pPDBHeader->page_size);
}

int
PDB7::GetStreamSize(int index)
{
    auto stream = streams.at(index);
    return stream->size() * this->pPDBHeader->page_size;
}

char*
PDB7::GetStreamLoc(int index)
{
    auto stream    = streams.at(index);
    auto pageIndex = stream->at(0);
    return GetPage(pageIndex);
}

StreamData
PDB7::ReadStream(int index)
{
    auto stream     = streams.at(index);
    auto sizeNeeded = stream->size() * this->pPDBHeader->page_size;
    char* buf       = new char[sizeNeeded];
    memset(buf, 0, sizeNeeded);

    for ( int i = 0; i < stream->size(); i++ )
    {
        auto pageIndex = stream->at(i);
        memcpy(
            buf + (i * this->pPDBHeader->page_size),
            pdbBuffer + (pageIndex * this->pPDBHeader->page_size),
            this->pPDBHeader->page_size);
    }

    StreamData pData;
    pData.data = buf;
    pData.size = sizeNeeded;

    return pData;
}

int
PDB7::GetPageCount(int stream_size)
{
    auto res = stream_size / this->pPDBHeader->page_size;
    if ( stream_size % this->pPDBHeader->page_size )
        res += 1;

    return res;
}

DebugInfo*
PDB7::GetModuleDebugInfo()
{
    if ( this->image_base == nullptr )
    {
        puts("No module, are you stupid?");
        return false;
    }

    IMAGE_DOS_HEADER* pDos = (IMAGE_DOS_HEADER*)this->image_base;
    IMAGE_NT_HEADERS* pNt  = (IMAGE_NT_HEADERS*)(image_base + pDos->e_lfanew);

    this->sectionCount = pNt->FileHeader.NumberOfSections;
    this->pSections    = (IMAGE_SECTION_HEADER*)((char*)pNt + sizeof(IMAGE_NT_HEADERS));

    auto pDebug =
        (IMAGE_DEBUG_DIRECTORY*)(pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress +
image_base);

    auto pDebugInfo = (DebugInfo*)(pDebug->AddressOfRawData + image_base);


    // memcpy( out, pDebugInfo->guid, sizeof( DebugInfo::guid ) );
    return pDebugInfo;
}

bool
PDB7::MatchPDBToFile(const char* path)
{
    char* bin = nullptr;
    if ( path == nullptr )
        bin = this->image_base;
    else
        bin = (char*)LoadLibraryA(path);

    if ( this->pdbBuffer == nullptr )
    {
        puts("No PDB to compare against");
        return true;
    }

    IMAGE_DOS_HEADER* pDos = (IMAGE_DOS_HEADER*)bin;
    IMAGE_NT_HEADERS* pNt  = (IMAGE_NT_HEADERS*)(bin + pDos->e_lfanew);

    this->sectionCount = pNt->FileHeader.NumberOfSections;
    this->pSections    = (IMAGE_SECTION_HEADER*)((char*)pNt + sizeof(IMAGE_NT_HEADERS));

    auto pDebug =
        (IMAGE_DEBUG_DIRECTORY*)(pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress + bin);
    auto pDebugInfo = (DebugInfo*)(pDebug->AddressOfRawData + bin);

    struct Stream1
    {
        int ver;
        int date;
        int age;
        GUID guid;
    };

    auto pInfoStream = (Stream1*)GetStreamLoc(GUIDStream);
    auto guid1       = pDebugInfo->guid;
    auto guid2       = pInfoStream->guid;

    if ( guid1.Data1 != guid2.Data1 )
        return false;

    if ( guid1.Data2 != guid2.Data2 )
        return false;

    if ( guid1.Data3 != guid2.Data3 )
        return false;

    return !memcmp(guid1.Data4, guid2.Data4, sizeof(guid1.Data4));
}

bool
PDB7::SetModule(char* base)
{
    if ( base == nullptr )
        return true; // do your thing dipshit

    this->image_base = base;
    auto res         = this->MatchPDBToFile();
    if ( !res )
    {
        this->image_base   = 0;
        this->pSections    = 0;
        this->sectionCount = 0;
    }

    return res;
}

void
PDB7::DumpStreams()
{
    for ( int i = 0; i < this->pRootStream->num_streams; i++ )
    {
        auto pData      = ReadStream(i);
        char name[1000] = {0};
        auto dirCreate  = CreateDirectoryA("./Dumps/", 0);
        if ( !dirCreate && GetLastError() != ERROR_ALREADY_EXISTS )
        {
            printf_s("Failed to create dir ((((\n");
            getchar();
            return;
        }
        sprintf_s(name, "Dumps/stream_%d.bin", i);
        std::ofstream of(name, std::ios::binary);
        of.write(pData->data, pData->size);
        delete pData->data;
        delete pData;
        of.close();
    }
}

bool
PDB7::DownloadPDB(char* modName, char* dlPath)
{
    auto pDebugInfo = this->GetModuleDebugInfo();
    if ( !pDebugInfo )
    {
        puts("No debug info, feelsbad?");
        return false;
    }

    auto guid = &pDebugInfo->guid;

    char* ctx         = 0;
    char* module_name = nullptr;

    if ( !_stricmp("ntoskrnl.exe", modName) )
    {
        // there are 4 possible names, ntoskrnl, ntkrnlmp, ntkrnlpa, and ntkrpamp. Loop through all to find the PDB
        // as theyre all called NTOSKRNL
        const char* names[] = {"ntoskrnl", "ntkrnlmp", "ntkrnlpa", "ntkrpamp"};
        for ( int i = 0; i < sizeof(names) / sizeof(char*); i++ )
        {
            auto curName = names[i];
            printf_s("Attempting kernel file name %s\n", curName);

            std::stringstream urlStream;
            urlStream << "http://msdl.microsoft.com/download/symbols/" << curName << ".pdb/";

            // blatantly ripped from drew0709's pdbparse.cpp cause fuck GUIDs
            // https://github.com/drew0709/pdbparse/blob/master/pdbparse/pdbparse.cpp#L74

            urlStream << std::setfill('0') << std::setw(8) << std::hex << guid->Data1 << std::setw(4) << std::hex
                      << guid->Data2 << std::setw(4) << std::hex << guid->Data3;
            for ( const auto i : guid->Data4 )
                urlStream << std::setw(2) << std::hex << +i;
            urlStream << pDebugInfo->age;

            urlStream << "/" << curName << ".pdb";
            // download this to ./modName.pdb

            puts("Attempting to download kernel file, be patient.");
            if ( URLDownloadToFileA(0, urlStream.str().c_str(), dlPath ? dlPath : "ntoskrnl.pdb", 0, 0) )
            {
                printf_s("Failed to download using url %s\nError %d\n", urlStream.str().c_str(), GetLastError());
                continue;
            }
            else
                return true;
        }
    }
    else
    {
        module_name = strtok_s(modName, ".", &ctx);

        // format: http://msdl.microsoft.com/download/symbols/pdbname.pdb/guid/pdbname.pdb
        // example: https://msdl.microsoft.com/download/symbols/ntkrnlmp.pdb/ F2C39CCB E477FA99 A815 CE04EC327B061
        // /ntkrnlmp.pdb for an ntkrnlmp.pdb with GUID of that F2 shit

        std::stringstream urlStream;
        urlStream << "http://msdl.microsoft.com/download/symbols/" << module_name << ".pdb/";

        // blatantly ripped from drew0709's pdbparse.cpp cause fuck GUIDs
        // https://github.com/drew0709/pdbparse/blob/master/pdbparse/pdbparse.cpp#L74

        urlStream << std::setfill('0') << std::setw(8) << std::hex << guid->Data1 << std::setw(4) << std::hex
                  << guid->Data2 << std::setw(4) << std::hex << guid->Data3;
        for ( const auto i : guid->Data4 )
            urlStream << std::setw(2) << std::hex << +i;
        urlStream << pDebugInfo->age;

        urlStream << "/" << module_name << ".pdb";
        // download this to ./modName.pdb

        char name[100] = {0};
        sprintf_s(name, "%s.pdb", module_name);

        puts("Attempting to download file, be patient.");
        if ( URLDownloadToFileA(0, urlStream.str().c_str(), dlPath ? dlPath : name, 0, 0) )
        {
            printf_s("Failed to download using url %s\nError %d\n", urlStream.str().c_str(), GetLastError());
            return false;
        }

        return true;
    }

    return false;
}

void
PDB7::DumpSymbols()
{
    SymbolInfo* pSymbolInfo = nullptr;

    std::ofstream of("sym_dump.txt");
    std::stringstream sstream;

    for ( char* base = pSymbolStream->data; base < (pSymbolStream->data + pSymbolStream->size);
          base += pSymbolInfo->length + 2 )
    {
        pSymbolInfo = (SymbolInfo*)base;
        if ( pSymbolInfo->magic != 0x110E ) // not a symbol (
            break;                          // no more symbols left

        sstream << pSymbolInfo->symbol << "\n";
    }

    of.write(sstream.str().c_str(), sstream.str().length());

    return;
}


char*
PDB7::FindSymbol(const char* sym)
{
    SymbolInfo* pSymbolInfo = nullptr;

    for ( char* base = pSymbolStream->data; base < (pSymbolStream->data + pSymbolStream->size);
          base += pSymbolInfo->length + 2 )
    {
        pSymbolInfo = (SymbolInfo*)base;
        if ( pSymbolInfo->magic != 0x110E ) // not a symbol (
            break;                          // no more symbols left

        if ( !_stricmp(pSymbolInfo->symbol, sym) )
        {
            if ( this->image_base )
            {
                if ( pSymbolInfo->section > this->sectionCount )
                {
                    printf_s("Section of symbol non-existent, check this shit out!\n");
                    printf_s("%s found at section %02X:%08X", pSymbolInfo->section, pSymbolInfo->offset);
                }
                else
                {
                    auto secBase = this->pSections[pSymbolInfo->section - 1].VirtualAddress;
                    return (secBase + pSymbolInfo->offset + this->image_base);
                }
            }
            else
            {
                printf_s("No module loaded, can only give section:offset\n");
                printf_s("%s found at section %02X:%08X\n", sym, pSymbolInfo->section, pSymbolInfo->offset);
            }
        }
    }


    return 0;
}
*/

#pragma endregion

} // namespace pwn::windows::symbols
