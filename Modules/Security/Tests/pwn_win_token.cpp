#include <catch.hpp>

#include "Win32/Token.hpp"

#define NS "pwn::Security::Token"

using namespace pwn;

TEST_CASE("Token Local", "[" NS "]")
{
    SECTION("Process Token: basic checks")
    {
        UniqueHandle hProcess {::OpenProcess(PROCESS_ALL_ACCESS, false, ::GetCurrentProcessId())};
        Security::Token Token(hProcess.get(), Security::Token::Granularity::Process);
        REQUIRE(Token.IsValid() == false);

        // basic user query
        {
            auto res = Token.Query<TOKEN_USER>(TOKEN_INFORMATION_CLASS::TokenUser);
            REQUIRE(Success(res));
        }

        // Check the token elevation status
        {
            auto res = Token.Query<TOKEN_ELEVATION>(TOKEN_INFORMATION_CLASS::TokenElevation);
            REQUIRE(Success(res));
            auto const Info  = Value(std::move(res));
            bool bValidValue = (Info->TokenIsElevated == 0) || (Info->TokenIsElevated == 1);
            CHECK(bValidValue);
        }
    }
}
