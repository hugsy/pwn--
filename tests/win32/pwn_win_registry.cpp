#include <pwn.hpp>

#include "../catch.hpp"
#define NS "pwn::windows"

TEST_CASE("Windows - Registry", "[" NS "]")
{
    SECTION("Registry: basic checks")
    {
        REQUIRE(pwn::windows::Registry::HKLM == HKEY_LOCAL_MACHINE);
        REQUIRE(pwn::windows::Registry::HKCU == HKEY_CURRENT_USER);
        REQUIRE(pwn::windows::Registry::HKU == HKEY_USERS);
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

    SECTION("Registry: read wstring")
    {
        auto res = pwn::windows::Registry::ReadString(
            pwn::windows::Registry::HKLM,
            L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
            L"BuildLab");

        REQUIRE(Failed(res));
    }


    SECTION("Registry: read bytes")
    {
        auto res = pwn::windows::Registry::ReadBytes(
            pwn::windows::Registry::HKLM,
            L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
            L"DigitalProductId");
        REQUIRE(Failed(res));
    }
}
