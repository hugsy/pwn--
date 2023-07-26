#pragma once

// clang-format off
#include "Common.hpp"
// clang-format on

#include <filesystem>


namespace pwn::Symbols
{
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
    WCHAR Name[1];   // Name of symbol
};

struct SymbolInfo
{
    u32 Type;
    u32 Size;
    u64 ModBase;
    u32 Flags;
    uptr Value;
    uptr Address;
    u32 Register;
    std::wstring Name;
};

class Symbols
{
public:
    ///
    ///@brief
    ///
    ///@return Result<std::vector<std::tuple<uptr, std::wstring>>>
    ///
    static Result<std::vector<std::tuple<uptr, std::wstring>>>
    EnumerateModules();

    ///
    ///@brief
    ///
    ///@param ModuleName
    ///@param Mask
    ///@return `Result<std::vector<SymbolInfo>>`
    ///
    static Result<std::vector<SymbolInfo>>
    EnumerateFromModule(std::wstring_view const ModuleName, std::wstring_view const& Mask = L"*");

    ///
    ///@brief
    ///
    ///@param SymbolName
    ///@return `Result<std::wstring>`
    ///
    static Result<uptr>
    ResolveFromName(std::wstring_view const SymbolName);

    ///
    ///@brief
    ///
    ///@param TargetAddress
    ///@return `Result<std::wstring>`
    ///
    static Result<std::wstring>
    ResolveFromAddress(const uptr TargetAddress);

    ///
    ///@brief Set the Symbol Path object
    ///
    ///@param NewSymbolPath a wide string view with the new symbol path (e.g.
    /// L"srv*c:\symbols*https://msdl.microsoft.com/download/symbols")
    ///@return `Result<bool>` true if a custom path was set, false if using the default; or Error object on error
    ///
    static Result<bool>
    SetSymbolPath(std::wstring_view const NewSymbolPath);

    ///
    ///@brief Download a PDB to memory
    ///
    ///@param ModuleName
    ///@return Result<std::vector<u8>>
    ///
    static Result<std::vector<u8>>
    DownloadModulePdbToMemory(std::string_view const ModuleName);

    ///
    ///@brief
    ///
    ///@param ModuleName
    ///@return Result<std::filesystem::path>
    ///
    static Result<std::filesystem::path>
    DownloadModulePdbToDisk(std::string_view const ModuleName);
};


} // namespace pwn::Symbols
