#include <catch.hpp>

#include "CTF/Win32/Process.hpp"
#include "Utils.hpp"

#define NS "CTF::Process"

TEST_CASE("CTF tests - Local", "[" NS "]")
{
    SECTION("Process basic")
    {
        // init
        CTF::Process p(L"C:\\Python310\\python.exe -i");

        // launch process
        {
            auto res = p.Spawn(false);
            REQUIRE(Success(res));
        }

        // receive prompt
        {
            auto res = p.recvuntil(">>> ");
            REQUIRE(Success(res));
            CHECK(Utils::StringLib::To<std::string>(Value(res)).ends_with(">>> "));
        }

        // send some command
        {
            auto res = p.sendline("print('hello pwn')");
            REQUIRE(Success(res));
        }

        // check the output of the received command
        {
            auto res = p.recvline();
            REQUIRE(Success(res));
            auto const output = Utils::StringLib::To<std::string>(Value(res));
            CHECK(output.size() == 11);
            CHECK(output.find("hello pwn") != std::string::npos);
        }
    }
}
