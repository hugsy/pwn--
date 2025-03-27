#include "Win32/Symbols.hpp"

#include "Handle.hpp"
#include "Log.hpp"
#include "Win32/API.hpp"
#include "Win32/Network.hpp"

using namespace pwn;

static HANDLE __hProcess                        = nullptr;
static HMODULE __hModule                        = nullptr;
static std::optional<std::wstring> __SymbolPath = std::nullopt;
static SharedHandle __spProcess                 = nullptr;


#pragma region Declaration

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


namespace pwn::Symbols
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

static HANDLE
GetHandle()
{

    if ( !__hProcess )
    {
        pwn::Resolver::dbghelp::SymSetOptions(SYMOPT_UNDNAME | SYMOPT_DEFERRED_LOADS);

        __hProcess = ::GetCurrentProcess(); // TODO: adjust

        if ( pwn::Resolver::dbghelp::SymInitializeW(__hProcess, nullptr, true) == FALSE )
        {
            Log::perror(L"SymInitialize()");
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
        (PIMAGE_DEBUG_DIRECTORY)(pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress +
                                 ModuleImageBase);
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
        return Err(Error::NotInitialized);
    }

    std::vector<std::tuple<uptr, std::wstring>> Modules;
    if ( pwn::Resolver::dbghelp::SymEnumerateModulesW64(hProcess, &EnumerateModulesW64Cb, &Modules) == FALSE )
    {
        Log::perror(L"SymEnumerateModulesW64()");
        return Err(Error::ExternalApiCallFailed);
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
Symbols::EnumerateFromModule(std::wstring_view const ModulePath, std::wstring_view const& Mask)
{
    HANDLE hProcess = GetHandle();
    if ( !hProcess )
    {
        return Err(Error::NotInitialized);
    }

    u64 BaseOfDll =
        pwn::Resolver::dbghelp::SymLoadModuleExW(hProcess, nullptr, ModulePath.data(), nullptr, 0, 0, nullptr, 0);
    if ( !BaseOfDll )
    {
        Log::perror(L"SymLoadModuleExW()");
        return Err(Error::ExternalApiCallFailed);
    }

    std::vector<SymbolInfo> ModuleSymbolInfo;
    if ( pwn::Resolver::dbghelp::SymEnumSymbolsW(hProcess, BaseOfDll, Mask.data(), &EnumSymProcCb, &ModuleSymbolInfo) ==
         FALSE )
    {
        Log::perror(L"SymEnumSymbolsW()");
        return Err(Error::ExternalApiCallFailed);
    }

    return Ok(ModuleSymbolInfo);
}


Result<uptr>
Symbols::ResolveFromName(std::wstring_view const SymbolName)
{
    HANDLE hProcess = GetHandle();
    if ( !hProcess )
    {
        return Err(Error::NotInitialized);
    }

    auto pBuffer          = std::make_unique<u8[]>(sizeof(SYMBOL_INFOW) + MAX_SYM_NAME * sizeof(u16));
    auto pSymbol          = reinterpret_cast<SYMBOL_INFOW*>(pBuffer.get());
    pSymbol->SizeOfStruct = sizeof(SYMBOL_INFOW);
    pSymbol->MaxNameLen   = MAX_SYM_NAME;

    if ( pwn::Resolver::dbghelp::SymFromNameW(hProcess, SymbolName.data(), pSymbol) == FALSE )
    {
        Log::perror(L"SymFromNameW()");
        return Err(Error::ExternalApiCallFailed);
    }

    return Ok((uptr)pSymbol->Address);
}


Result<std::wstring>
Symbols::ResolveFromAddress(const uptr TargetAddress)
{
    HANDLE hProcess = GetHandle();
    if ( !hProcess )
    {
        return Err(Error::NotInitialized);
    }

    auto pBuffer          = std::make_unique<u8[]>(sizeof(SYMBOL_INFOW) + MAX_SYM_NAME * sizeof(u16));
    auto pSymbol          = reinterpret_cast<SYMBOL_INFOW*>(pBuffer.get());
    pSymbol->SizeOfStruct = sizeof(SYMBOL_INFOW);
    pSymbol->MaxNameLen   = MAX_SYM_NAME;

    if ( pwn::Resolver::dbghelp::SymFromAddrW(hProcess, TargetAddress, nullptr, pSymbol) == FALSE )
    {
        Log::perror(L"SymFromAddrW()");
        return Err(Error::ExternalApiCallFailed);
    }

    return Ok(pSymbol->Name);
}

Result<bool>
Symbols::SetSymbolPath(std::wstring_view const NewSymbolPath)
{
    __SymbolPath = NewSymbolPath;
    if ( !__hProcess )
    {
        return Err(Error::InitializationFailed);
    }

    PCWSTR SymPath = __SymbolPath.has_value() ? __SymbolPath.value().c_str() : nullptr;
    if ( !SymPath )
    {
        return Ok(false);
    }

    if ( pwn::Resolver::dbghelp::SymSetSearchPathW(__hProcess, SymPath) == FALSE )
    {
        Log::perror(L"SymSetSearchPath()");
        return Err(Error::ExternalApiCallFailed);
    }

    return Ok(true);
}


Result<std::filesystem::path>
Symbols::DownloadModulePdbToDisk(std::string_view const ModuleNameWithExt)
{
    //
    // Load the module as data
    //
    const std::string_view ModuleName = ModuleNameWithExt.substr(0, ModuleNameWithExt.size() - 4);
    UniqueLibraryHandle hMod {::LoadLibraryExA(ModuleNameWithExt.data(), nullptr, LOAD_LIBRARY_AS_DATAFILE)};
    if ( !hMod )
    {
        return Err(Error::ExternalApiCallFailed);
    }

    DebugInfoSection* dbg = GetModuleDebugInfo((uptr)(hMod.get()) & ~0x0f);
    if ( !dbg )
    {
        return Err(Error::GenericError);
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
    auto dlRes = Net::HTTP::DownloadFile(url.str(), ModulePathWithPdb);
    if ( Failed(dlRes) )
    {
        return Error(dlRes);
    }

    return Ok(ModulePathWithPdb);
}


Result<std::vector<u8>>
Symbols::DownloadModulePdbToMemory(std::string_view const ModuleNameWithExt)
{
    //
    // Download PDB
    //
    auto dlRes = Symbols::DownloadModulePdbToDisk(ModuleNameWithExt);
    if ( Failed(dlRes) )
    {
        return Error(dlRes);
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
            return Err(Error::ExternalApiCallFailed);
        }

        if ( ::ReadFile(h.get(), RawPdb.data(), RawPdbFileSize, nullptr, nullptr) == FALSE )
        {
            return Err(Error::ExternalApiCallFailed);
        }
    }

    std::filesystem::remove(ModulePathWithPdb);
    return Ok(RawPdb);
}

#pragma endregion


} // namespace pwn::Symbols
