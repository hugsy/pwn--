#include <pwn.hpp>

#include "../catch.hpp"
#define NS "pwn::windows"

TEST_CASE("Token Local", "[" NS "]")
{
    SECTION("Token process - basic")
    {
        auto CurrentProcess = Value(pwn::windows::Process::Current());
        REQUIRE(CurrentProcess.IsValid() == true);
        pwn::windows::Token LocalToken;
        REQUIRE(LocalToken.IsValid() == false);

        LocalToken = CurrentProcess.Token;
        REQUIRE(LocalToken.IsValid() == true);

        auto res = LocalToken.Query<TOKEN_ELEVATION>(TokenElevation);
        REQUIRE(Success(res));
        auto const Info  = Value(res);
        bool bValidValue = (Info->TokenIsElevated == 0) || (Info->TokenIsElevated == 1);
        CHECK(bValidValue);
    }
}
