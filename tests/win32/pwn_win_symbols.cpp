#include <pwn.hpp>

#include "../catch.hpp"
#define NS "pwn::windows::Symbols"

using pwn::windows::symbols::Symbols;

TEST_CASE("Symbols lookup", "[" NS "]")
{
    SECTION("Check modules")
    {
        auto res = Symbols::EnumerateModules();
        REQUIRE(Success(res));

        auto Modules = Value(res);
        REQUIRE(Modules.size() > 0);
    }

    SECTION("Resolve symbols")
    {
        auto res = Symbols::EnumerateFromModule(L"kernel32", L"GetProc*");
        REQUIRE(Success(res));
        auto const& Symbols = Value(res);
        REQUIRE(Symbols.size() == 1);
        const uptr ExpectedAddresss = (uptr)::GetProcAddress(::LoadLibraryA("kernel32"), "GetProcAddress");
        REQUIRE(ExpectedAddresss > 0);
        REQUIRE(Symbols[0].Address == ExpectedAddresss);
    }


    SECTION("Download PDB, store in memory modules")
    {
        auto res = pwn::win::sym::Symbols::DownloadModulePdbToMemory("kernel32.dll");
        REQUIRE(Success(res));

        auto pdbData = Value(res);
        REQUIRE(pdbData.size() > 0);
    }


    // SECTION("Resolve a symbol from name")
    // {
    //     std::wstring_view const SymbolName = L"kernel32!GetProcAddress";
    //     auto res                           = Symbols::ResolveFromName(SymbolName);
    //     REQUIRE(Success(res));
    //     auto ResultAddress = Value(res);
    //     REQUIRE(ResultAddress > 0);
    //     const uptr ExpectedAddresss = (uptr)::GetProcAddress(::LoadLibraryA("kernel32"), "GetProcAddress");
    //     REQUIRE(ExpectedAddresss > 0);
    //     REQUIRE(ResultAddress == ExpectedAddresss);
    // }
}
