#include "symbols.hpp"

#include "log.hpp"

static HANDLE __hProcess = nullptr;
static HMODULE __hModule = nullptr;

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


namespace pwn::windows
{

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
                SymLoadModuleExW = (SymLoadModuleExW_t)::GetProcAddress(__hModule, "SymLoadModuleExW");
                SymEnumSymbolsW  = (SymEnumSymbolsW_t)::GetProcAddress(__hModule, "SymEnumSymbolsW");
                SymFromNameW     = (SymFromNameW_t)::GetProcAddress(__hModule, "SymFromNameW");
                SymFromAddrW     = (SymFromAddrW_t)::GetProcAddress(__hModule, "SymFromAddrW");
            }

            // Initialize the debug engine for the target process
            {
                ::SymSetOptions(SYMOPT_UNDNAME | SYMOPT_DEFERRED_LOADS);

                __hProcess = ::GetCurrentProcess(); // TODO: adjust

                if ( SymInitializeW(__hProcess, nullptr, true) == FALSE )
                {
                    log::perror(L"SymInitialize()");
                    return nullptr;
                }
            }
        }
    }
    return __hProcess;
}

Result<std::vector<std::tuple<uptr, std::wstring>>>
Symbols::EnumerateModules()
{
    HANDLE hProcess = GetHandle();
    if ( !hProcess )
    {
        return Err(ErrorCode::NotInitialized);
    }
    std::vector<std::tuple<uptr, std::wstring>> Modules;

    auto EnumModulesCb = [&Modules](PCWSTR ModuleName, DWORD64 BaseOfDll, PVOID UserContext) -> BOOL
    {
        UnreferencedParameter(UserContext);
        Modules.push_back({(uptr)BaseOfDll, std::wstring {ModuleName}});
        return TRUE;
    };

    if ( SymEnumerateModulesW64(hProcess, &EnumModulesCb, nullptr) == FALSE )
    {
        log::perror(L"SymEnumerateModulesW64()");
        return Err(ErrorCode::ExternalApiCallFailed);
    }

    return Ok(Modules);
}


Result<std::vector<SymbolInfo>>
Symbols::EnumerateFromModule(std::wstring_view const& ModuleName, std::wstring_view const& Mask)
{
    HANDLE hProcess = GetHandle();
    if ( !hProcess )
    {
        return Err(ErrorCode::NotInitialized);
    }

    std::vector<SymbolInfo> ModuleSymbolInfo;
    auto EnumSymProc = [&ModuleSymbolInfo](SYMBOL_INFOW* pSymInfo, ULONG SymbolSize, PVOID UserContext) -> bool
    {
        UnreferencedParameter(UserContext);
        ModuleSymbolInfo.push_back(CreateSymbolInfo(pSymInfo));
        return true;
    };

    u64 BaseOfDll = SymLoadModuleExW(hProcess, nullptr, ModuleName.data(), nullptr, 0, 0, nullptr, 0);
    if ( !BaseOfDll )
    {
        log::perror(L"SymLoadModuleExW()");
        return Err(ErrorCode::ExternalApiCallFailed);
    }

    if ( ::SymEnumSymbolsW(hProcess, BaseOfDll, Mask.data(), &EnumSymProc, nullptr) == FALSE )
    {
        log::perror(L"SymEnumSymbolsW()");
        return Err(ErrorCode::ExternalApiCallFailed);
    }

    return Ok(ModuleSymbolInfo);
}


Result<std::wstring>
Symbols::ResolveFromName(const uptr TargetAddress, std::wstring_view const& SymbolName)
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

    return Ok(std::wstring {pSymbol->Name});
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

} // namespace pwn::windows