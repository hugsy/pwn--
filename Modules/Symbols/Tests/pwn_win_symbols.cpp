#include <catch.hpp>

#include "Win32/Symbols.hpp"

#define NS "pwn::windows::Symbols"

using namespace pwn;

TEST_CASE("Symbols lookup", "[" NS "]")
{
    SECTION("Check modules")
    {
        auto res = Symbols::Symbols::EnumerateModules();
        REQUIRE(Success(res));

        auto Modules = Value(res);
        REQUIRE(Modules.size() > 0);
    }

    SECTION("Resolve symbols")
    {
        auto res = Symbols::Symbols::EnumerateFromModule(L"C:\\Windows\\System32\\kernel32.dll", L"GetProcA*ess");
        REQUIRE(Success(res));
        auto Symbols = Value(std::move(res));
        REQUIRE(Symbols.size() == 1);
        const uptr ModuleBaseAddress = (uptr)::LoadLibraryA("kernel32");
        const uptr ExpectedAddresss  = (uptr)::GetProcAddress((HMODULE)ModuleBaseAddress, "GetProcAddress");
        REQUIRE(ExpectedAddresss > 0);
        REQUIRE((Symbols[0].Address - Symbols[0].ModBase) == (ExpectedAddresss - ModuleBaseAddress));
    }


    SECTION("Download PDB, store in memory modules")
    {
        auto res = Symbols::Symbols::DownloadModulePdbToMemory("kernel32.dll");
        REQUIRE(Success(res));

        auto pdbData = Value(std::move(res));
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
