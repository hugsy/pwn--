#include "../catch.hpp"

#include <pwn.hpp>
#define NS "pwn::win::system"



TEST_CASE( "check page size", "[" NS "]" )
{
    REQUIRE( pwn::win::system::pagesize() == 0x1000 );
}