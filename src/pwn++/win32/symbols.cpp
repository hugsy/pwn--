#include "symbols.hpp"

#include "log.hpp"

// TODO: make it dynamic?
#pragma comment(lib, "Dbghelp.lib")

static HANDLE __hProcess = nullptr;

namespace pwn::windows
{

inline HANDLE
GetHandle()
{
    if ( !__hProcess )
    {
        ::SymSetOptions(SYMOPT_UNDNAME | SYMOPT_DEFERRED_LOADS);

        __hProcess = GetCurrentProcess(); // TODO: adjust

        if ( ::SymInitialize(__hProcess, nullptr, true) == FALSE )
        {
            log::perror(L"SymInitialize()");
            return nullptr;
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
        return Err(ErrorCode::InitializationFailed);
    }
    std::vector<std::tuple<uptr, std::wstring>> Modules;

    auto EnumModulesCb = [&Modules](PCWSTR ModuleName, DWORD64 BaseOfDll, PVOID UserContext) -> BOOL
    {
        UnreferencedParameter(UserContext);
        Modules.push_back({(uptr)BaseOfDll, std::wstring {ModuleName}});
        return TRUE;
    };

    if ( ::SymEnumerateModulesW64(hProcess, (PSYM_ENUMMODULES_CALLBACKW64)&EnumModulesCb, nullptr) == FALSE )
    {
        log::perror(L"SymEnumerateModulesW64()");
        return Err(ErrorCode::ExternalApiCallFailed);
    }

    return Ok(Modules);
}


Result<std::vector<SYMBOL_INFO>>
Symbols::EnumerateFromModule(std::wstring_view const& ModuleName, std::wstring_view const& Mask)
{
    HANDLE hProcess = GetHandle();
    if ( !hProcess )
    {
        return Err(ErrorCode::InitializationFailed);
    }

    std::vector<SYMBOL_INFO> ModuleSymbolInfo;
    auto EnumSymProc = [&ModuleSymbolInfo](PSYMBOL_INFO pSymInfo, ULONG SymbolSize, PVOID UserContext) -> bool
    {
        UnreferencedParameter(UserContext);
        ModuleSymbolInfo.push_back(*pSymInfo);
        return true;
    };

    u64 BaseOfDll = ::SymLoadModuleExW(hProcess, nullptr, ModuleName.data(), nullptr, 0, 0, nullptr, 0);
    if ( !BaseOfDll )
    {
        log::perror(L"SymLoadModuleExW()");
        return Err(ErrorCode::ExternalApiCallFailed);
    }

    if ( ::SymEnumSymbolsW(hProcess, BaseOfDll, Mask.data(), (PSYM_ENUMERATESYMBOLS_CALLBACKW)&EnumSymProc, nullptr) ==
         FALSE )
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
        return Err(ErrorCode::InitializationFailed);
    }

    auto pBuffer          = std::make_unique<u8[]>(sizeof(SYMBOL_INFOW) + MAX_SYM_NAME * sizeof(u16));
    auto pSymbol          = reinterpret_cast<PSYMBOL_INFOW>(pBuffer.get());
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
        return Err(ErrorCode::InitializationFailed);
    }

    auto pBuffer          = std::make_unique<u8[]>(sizeof(SYMBOL_INFOW) + MAX_SYM_NAME * sizeof(u16));
    auto pSymbol          = reinterpret_cast<PSYMBOL_INFOW>(pBuffer.get());
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
