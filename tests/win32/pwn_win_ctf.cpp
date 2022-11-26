#include <pwn.hpp>

#include "../catch.hpp"
#define NS "pwn::windows::ctf"

TEST_CASE("CTF tests - Local", "[" NS "]")
{
    SECTION("Process basic")
    {
        // init
        pwn::ctf::Process p(L"\"C:\\Python310\\python.exe\" -i");

        // launch process
        {
            auto res = p.Spawn(false);
            REQUIRE(Success(res));
        }

        // receive prompt
        {
            auto res = p.recvuntil(">>> ");
            REQUIRE(Success(res));
            CHECK(pwn::utils::StringLib::To<std::string>(Value(res)).ends_with(">>> "));
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
            auto const output = pwn::utils::StringLib::To<std::string>(Value(res));
            CHECK(output.size() == 11);
            CHECK(output.find("hello pwn") != std::string::npos);
        }
    }
}


TEST_CASE("CTF tests - Remote", "[" NS "]")
{
}
