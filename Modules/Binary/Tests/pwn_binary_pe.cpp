#include <catch.hpp>

#include "Win32/PE.hpp"

using namespace pwn;

#define NS "Binary::PE"

TEST_CASE("PE file parser", "[" NS "]")
{
    auto res = Binary::PE::Parse(L"c:\\windows\\system32\\kernel32.dll");
    REQUIRE(Success(res));
    const auto pe = Value(res);
    REQUIRE(pe.IsValid());

    SECTION("Basic checks")
    {
        REQUIRE(pe.Sections().size() > 1);
        REQUIRE(pe.DataDirectories().size() > 1);
        REQUIRE(pe.ImportTable().size() > 1);
        REQUIRE(pe.ExportTable().size() > 1);
    }

    SECTION("Import parsing")
    {
        for ( auto const& entry : pe.ImportTable() )
        {
            REQUIRE(entry.Functions.size() != 0);
            REQUIRE(entry.Name2 != "");
            for ( auto const& ufn : entry.Functions )
            {
                if ( pe.Is64b() )
                {
                    const auto& fn = std::get<Binary::PE::PeThunkData64>(ufn);
                    REQUIRE(fn.Name != "");
                    REQUIRE(fn.u1.AddressOfData > 0);
                }
                else
                {
                    const auto& fn = std::get<Binary::PE::PeThunkData32>(ufn);
                    REQUIRE(fn.Name != "");
                    REQUIRE(fn.u1.AddressOfData > 0);
                }
            }
        }
    }

    SECTION("Export parsing")
    {
        for ( auto const& entry : pe.ExportTable() )
        {
            REQUIRE(entry.Name != "");
            REQUIRE(entry.Ordinal != 0);
            REQUIRE(entry.Rva != 0);
            REQUIRE(entry.NameOffset != 0);
            INFO("Found kernel32!" << entry.Name);
        }
    }
}
