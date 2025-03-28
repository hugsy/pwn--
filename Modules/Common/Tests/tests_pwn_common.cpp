#define CATCH_CONFIG_MAIN

#include <catch2/catch_test_macros.hpp>

#include "Common.hpp"

#define NS "Common"


Result<int>
TestFunc1(uint32_t i)
{
    if ( i == 42 )
    {
        return Ok(1);
    }

    return Err(Error::RuntimeError);
}


Result<std::vector<int>>
TestFunc2(uint32_t i)
{
    if ( i == 42 )
    {
        return Ok(std::vector<int> {1, 2, 3});
    }

    return Err(Error::RuntimeError);
}


TEST_CASE("Error class", "[" NS "]")
{
    SECTION("Basic types - inline")
    {
        CHECK(Success(TestFunc1(42)));
        CHECK_FALSE(Success(TestFunc1(1)));
        REQUIRE(Failed(TestFunc1(1)));
        CHECK(TestFunc1(1).error() == Error::RuntimeError);
        CHECK(Value(TestFunc1(42)) == 1);
        // CHECK_THROWS_AS(Value(TestFunc1(1)), std::bad_variant_access);
        // CHECK(
        //     TestFunc1(1)
        //         .or_else(
        //             [](auto const&)
        //             {
        //                 return 2;
        //             })
        //         .value() == 2);
    }

    SECTION("Basic types - reference")
    {
        auto ok  = TestFunc1(42);
        auto nok = TestFunc1(1);

        CHECK(Success(ok));
        CHECK_FALSE(Success(nok));
        CHECK(Failed(nok));
        CHECK(nok.error() == Error::RuntimeError);
        CHECK(Value(ok) == 1);
        // CHECK(nok.value_or(2) == 2);
    }

    SECTION("Advanced types")
    {
        // simple test
        CHECK(Success(TestFunc2(42)));
        CHECK_FALSE(Success(TestFunc2(1)));
    }
}
