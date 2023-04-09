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
        REQUIRE(pe.ExportTable().size() > 1);
    }

    SECTION("Import parsing")
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
