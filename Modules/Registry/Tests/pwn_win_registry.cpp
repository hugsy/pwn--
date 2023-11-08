#include <catch2/catch_test_macros.hpp>

#include "Win32/Registry.hpp"
#define NS "pwn::Registry"

using namespace pwn;

TEST_CASE("Windows::Registry - Read Value", "[" NS "]")
{
    SECTION("Registry: basic checks")
    {
        REQUIRE(Registry::Registry::HKLM == HKEY_LOCAL_MACHINE);
        REQUIRE(Registry::Registry::HKCU == HKEY_CURRENT_USER);
        REQUIRE(Registry::Registry::HKU == HKEY_USERS);
    }

    SECTION("Registry: not existing")
    {
        // Bad Key
        {
            auto res = Registry::Registry::ReadDword(
                Registry::Registry::HKLM,
                L"SYSTEM\\CurrentControlSet\\Control\\LsaFoobar",
                L"RunAsPplButDontReallyExist");

            REQUIRE(Failed(res));
            CHECK(Error(res).Code == ErrorCode::ExternalApiCallFailed);
        }

        // Bad value
        {
            auto res = Registry::Registry::ReadDword(
                Registry::Registry::HKLM,
                L"SYSTEM\\CurrentControlSet\\Control\\Lsa",
                L"RunAsPplButDontReallyExist");

            REQUIRE(Failed(res));
            CHECK(Error(res).Code == ErrorCode::NotFound);
        }
    }

    SECTION("Registry: read dword")
    {
        auto res = Registry::Registry::ReadDword(
            Registry::Registry::HKLM,
            L"Software\\Microsoft\\Windows NT\\CurrentVersion",
            L"CurrentMajorVersionNumber");

        REQUIRE(Success(res));
        CHECK(Value(res) == 10);
    }

    SECTION("Registry: read qword")
    {
    }

    SECTION("Registry: read string as wstring")
    {
        auto res = Registry::Registry::ReadWideString(
            Registry::Registry::HKLM,
            L"SYSTEM\\CurrentControlSet\\Control\\Session Manager\\KnownDLLs",
            L"user32");

        REQUIRE(Success(res));
        CHECK(Value(res) == L"user32.dll");
    }

    SECTION("Registry: read string array")
    {
        auto res = Registry::Registry::ReadWideStringArray(
            Registry::Registry::HKLM,
            L"SYSTEM\\CurrentControlSet\\Control",
            L"PreshutdownOrder");

        REQUIRE(Success(res));
        auto const& value = Value(res);
        CHECK(value.size() >= 1);

        for ( auto const& entry : value )
        {
            CHECK(entry.size() >= 0);
        }
    }

    SECTION("Registry: read bytes")
    {
        auto res = Registry::Registry::ReadBytes(
            Registry::Registry::HKLM,
            L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
            L"DigitalProductId");

        REQUIRE(Success(res));
        auto const& raw = Value(res);
        const u16 sz    = *((u16*)&raw[0]);
        CHECK(raw.size() == sz);
    }
}


TEST_CASE("Windows::Registry - Write Value", "[" NS "]")
{
}


TEST_CASE("Windows::Registry - Enumerate Keys", "[" NS "]")
{
    auto res =
        Registry::Registry::ListKeys(Registry::Registry::HKCU, L"Software\\Microsoft\\Windows NT\\CurrentVersion");
    REQUIRE(Success(res));
    auto const& entries = Value(res);
    CHECK(entries.size() > 0);
}


TEST_CASE("Windows::Registry - Enumerate Values", "[" NS "]")
{
    auto res = Registry::Registry::ListValues(
        Registry::Registry::HKCU,
        L"Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon");
    REQUIRE(Success(res));
    auto const& entries = Value(res);
    CHECK(entries.size() > 0);
}
