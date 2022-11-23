#include <pwn.hpp>

#include "../catch.hpp"
#define NS "pwn::windows"

TEST_CASE("Windows::Registry - Read Value", "[" NS "]")
{
    SECTION("Registry: basic checks")
    {
        REQUIRE(pwn::windows::Registry::HKLM == HKEY_LOCAL_MACHINE);
        REQUIRE(pwn::windows::Registry::HKCU == HKEY_CURRENT_USER);
        REQUIRE(pwn::windows::Registry::HKU == HKEY_USERS);
    }

    SECTION("Registry: not existing")
    {
        // Bad Key
        {
            auto res = pwn::windows::Registry::ReadDword(
                pwn::windows::Registry::HKLM,
                L"SYSTEM\\CurrentControlSet\\Control\\LsaFoobar",
                L"RunAsPplButDontReallyExist");

            REQUIRE(Failed(res));
            CHECK(Error(res).code == ErrorCode::ExternalApiCallFailed);
        }

        // Bad value
        {
            auto res = pwn::windows::Registry::ReadDword(
                pwn::windows::Registry::HKLM,
                L"SYSTEM\\CurrentControlSet\\Control\\Lsa",
                L"RunAsPplButDontReallyExist");

            REQUIRE(Failed(res));
            CHECK(Error(res).code == ErrorCode::NotFound);
        }
    }

    SECTION("Registry: read dword")
    {
        auto res = pwn::windows::Registry::ReadDword(
            pwn::windows::Registry::HKLM,
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
        auto res = pwn::windows::Registry::ReadWideString(
            pwn::windows::Registry::HKLM,
            L"SYSTEM\\CurrentControlSet\\Control\\Session Manager\\KnownDLLs",
            L"user32");

        REQUIRE(Success(res));
        CHECK(Value(res) == L"user32.dll");
    }

    SECTION("Registry: read string array")
    {
        auto res = pwn::windows::Registry::ReadWideStringArray(
            pwn::windows::Registry::HKLM,
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
        auto res = pwn::windows::Registry::ReadBytes(
            pwn::windows::Registry::HKLM,
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
    auto res = pwn::windows::Registry::ListKeys(
        pwn::windows::Registry::HKCU,
        L"Software\\Microsoft\\Windows NT\\CurrentVersion");
    REQUIRE(Success(res));
    auto const& entries = Value(res);
    CHECK(entries.size() > 0);
}


TEST_CASE("Windows::Registry - Enumerate Values", "[" NS "]")
{
    auto res = pwn::windows::Registry::ListValues(
        pwn::windows::Registry::HKCU,
        L"Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon");
    REQUIRE(Success(res));
    auto const& entries = Value(res);
    CHECK(entries.size() > 0);
}
