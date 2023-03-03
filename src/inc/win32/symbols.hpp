#pragma once

// clang-format off
#include "common.hpp"
// clang-format on

#include <filesystem>


namespace pwn::windows::symbols
{

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
    EnumerateFromModule(std::wstring_view const& ModuleName, std::wstring_view const& Mask = L"*");

    ///
    ///@brief
    ///
    ///@param SymbolName
    ///@return `Result<std::wstring>`
    ///
    static Result<uptr>
    ResolveFromName(std::wstring_view const& SymbolName);

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
    SetSymbolPath(std::wstring_view const& NewSymbolPath);

    ///
    ///@brief Download a PDB to memory
    ///
    ///@param ModuleName
    ///@return Result<std::vector<u8>>
    ///
    static Result<std::vector<u8>>
    DownloadModulePdbToMemory(std::string_view const& ModuleName);

    ///
    ///@brief
    ///
    ///@param ModuleName
    ///@return Result<std::filesystem::path>
    ///
    static Result<std::filesystem::path>
    DownloadModulePdbToDisk(std::string_view const& ModuleName);
};

/*
#pragma pack(push, 1)
struct DBIHeader
{
    u32 sig;
    u32 version;
    u32 age;
    u16 globalStreamIndex;
    u16 pdbBuildNumber;
    u16 publicStreamIndex;
    u16 dllVersion;
    u16 symbolStreamIndex;

private:
    u8 reserved[44];
};

struct SymbolInfo2
{
    u16 length;
    u16 magic; // 0x110E
    u32 flags;
    u32 offset;
    u16 section;
    u8 symbol[];
};

struct RootStream7
{
    int num_streams;
    int stream_sizes[]; // num_streams
};
#pragma pack(pop)


class PDB7
{
public:
    PDB7();

    PDB7(std::string_view const& PdbPath);

    bool
    MatchPdbBToFile(std::optional<std::string_view> Path = std::nullopt);

    bool
    SetModule(std::string_view const& BaseName);

    void
    DumpStreams();

    void
    DumpSymbols();

    bool
    DownloadPdb(std::string_view const& ModuleName, std::optional<std::filesystem::path> DownloadPath = std::nullopt);

    char*
    FindSymbol(std::string_view const& SymbolName);


private:
    enum class ImportantStreams : u8
    {
        GUIDStream = 1,
        DBIStream  = 3, // Contains structure which tells you what stream symbols are found (offset 20)
    };

    // ASSUMING VERSION 7
    struct PDBHeader7
    {
        // const char *signature = "Microsoft C/C++ MSF 7.00\r\n\x1A""DS\0\0\0";
        u8 signature[0x20];
        u32 page_size;
        u32 allocation_table_pointer;
        u32 file_page_count;
        u32 root_stream_size;
        u32 reserved;
        u32 root_stream_page_number_list_number;
    };

    struct StreamData
    {
        char* data;
        int size;
    };

    struct DebugInfo
    {
        char magic[4]; // RSDS
        GUID guid;
        int age;
        char pdb_path[];
    };

    char*
    GetPage(int index);

    int
    GetStreamSize(int index);

    char*
    GetStreamLoc(int index);

    StreamData
    ReadStream(int index);

    int
    GetPageCount(int stream_size);

    DebugInfo
    GetModuleDebugInfo();


    std::map<int, std::vector<int>*> streams;

    DBIHeader* pDBIHeader           = nullptr;
    StreamData* pSymbolStream       = nullptr;
    u8* image_base                  = nullptr; // base of image relating to PDB
    usize sectionCount              = 0;
    IMAGE_SECTION_HEADER* pSections = nullptr;
    PDBHeader7* pPDBHeader          = nullptr;
    RootStream7* pRootStream        = nullptr;
    u8* pdbBuffer                   = nullptr;
};
*/

} // namespace pwn::windows::symbols


namespace pwn::windows
{
// aliasing
namespace sym = symbols;
} // namespace pwn::windows
