#include <catch.hpp>

#include "Win32/Process.hpp"
#include "Win32/Token.hpp"
#define NS "pwn::Security::Token"

TEST_CASE("Token Local", "[" NS "]")
{
    SECTION("Process Token: basic checks")
    {
        auto CurrentProcess = Value(Process::Process::Current());
        REQUIRE(CurrentProcess.IsValid() == true);
        Security::Token BadToken;
        REQUIRE(BadToken.IsValid() == false);

        Security::Token& LocalToken = CurrentProcess.Token;
        REQUIRE(LocalToken.IsValid() == true);

        auto res = LocalToken.Query<TOKEN_ELEVATION>(TokenElevation);
        REQUIRE(Success(res));
        auto const Info  = Value(res);
        bool bValidValue = (Info->TokenIsElevated == 0) || (Info->TokenIsElevated == 1);
        CHECK(bValidValue);
    }
}
