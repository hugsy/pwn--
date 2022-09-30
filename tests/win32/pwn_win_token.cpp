#include <pwn.hpp>

#include "../catch.hpp"
#define NS "pwn::windows"

TEST_CASE("Token Local", "[" NS "]")
{
    SECTION("Process Token: basic checks")
    {
        auto CurrentProcess = Value(pwn::windows::Process::Current());
        REQUIRE(CurrentProcess.IsValid() == true);
        pwn::windows::Token BadToken;
        REQUIRE(BadToken.IsValid() == false);

        pwn::windows::Token& LocalToken = CurrentProcess.Token;
        REQUIRE(LocalToken.IsValid() == true);

        auto res = LocalToken.Query<TOKEN_ELEVATION>(TokenElevation);
        REQUIRE(Success(res));
        auto const Info  = Value(res);
        bool bValidValue = (Info->TokenIsElevated == 0) || (Info->TokenIsElevated == 1);
        CHECK(bValidValue);
    }
}
