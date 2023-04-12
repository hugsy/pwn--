#include <catch.hpp>

#include "Win32/PE.hpp"

using namespace pwn;

#define NS "Binary::PE"

TEST_CASE("Native PE file parser", "[" NS "]")
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
        REQUIRE(pe.ExceptionTable().size() > 1);
        REQUIRE(pe.DelayLoadTable().size() > 1);
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
            REQUIRE(entry.Rva != 0);
            REQUIRE(entry.NameOffset != 0);
        }
    }

    SECTION("Exception parsing")
    {
        for ( auto const& entry : pe.ExceptionTable() )
        {
            REQUIRE(entry.BeginAddress != 0);
            REQUIRE(entry.EndAddress != 0);
#ifndef _ARM64_
            REQUIRE(entry.UnwindInfoAddress != 0);
#endif // _ARM64_
        }
    }

    SECTION("DelayImport parsing")
    {
        const bool Is64b = pe.Is64b();

        for ( auto const& entry : pe.DelayLoadTable() )
        {
            REQUIRE(entry.Attributes.AllAttributes != 0);
            REQUIRE(entry.DllName != "");
            REQUIRE(entry.Functions.size() > 0);

            for ( auto const& fn : entry.Functions )
            {
                std::visit(
                    overloaded {
                        [](Binary::PE::PeThunkData32 const& ThunkData)
                        {
                            REQUIRE(ThunkData.u1.AddressOfData != 0);
                            REQUIRE(ThunkData.Name != "");
                            return true;
                        },
                        [](Binary::PE::PeThunkData64 const& ThunkData)
                        {
                            REQUIRE(ThunkData.u1.AddressOfData != 0);
                            REQUIRE(ThunkData.Name != "");
                            return true;
                        }},
                    fn);
            }
        }
    }

    SECTION("Debug parsing")
    {
        for ( auto const& DebugEntry : pe.DebugTable() )
        {
            REQUIRE(DebugEntry.AddressOfRawData != 0);
            REQUIRE(DebugEntry.Type != 0);
            REQUIRE(DebugEntry.SizeOfData != 0);
            REQUIRE(DebugEntry.PointerToRawData != 0);
        }
    }
}

TEST_CASE(".NET PE parse", "[" NS "]")
{
    auto res = Binary::PE::Parse(L"C:\\Program Files\\dotnet\\shared\\Microsoft.NETCore.App\\7.0.5\\mscorlib.dll");
    REQUIRE(Success(res));
    const auto pe = Value(res);
    REQUIRE(pe.IsValid());

    SECTION("COM parsing")
    {
    }
}
