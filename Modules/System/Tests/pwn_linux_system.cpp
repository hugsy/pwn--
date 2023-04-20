#include "../catch.hpp"

#include <pwn.hpp>
#define NS "pwn::linux::system"



TEST_CASE( "check page size", "[" NS "]" )
{
    REQUIRE( pwn::linux::system::pagesize() == 0x1000 );
}