#define CATCH_CONFIG_MAIN

#include "catch.hpp"


//
// some dummy tests
//

#include <pwn.hpp>
#define NS "pwn"

TEST_CASE( "check version", "[" NS "]" )
{
    REQUIRE( pwn::version() != L"" );
    auto info = pwn::version_info();
    REQUIRE( std::get<0>(info) >= 0 );
    REQUIRE( std::get<1>(info) >= 0 );
}