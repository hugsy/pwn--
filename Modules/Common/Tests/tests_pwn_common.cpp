#define CATCH_CONFIG_MAIN

#include <catch.hpp>

#include "Common.hpp"

#define NS "Common"


Result<int>
TestFunc1(uint32_t i)
{
    if ( i == 42 )
    {
        return Ok(1);
    }

    return Err(ErrorCode::RuntimeError);
}


Result<std::vector<int>>
TestFunc2(uint32_t i)
{
    if ( i == 42 )
    {
        return Ok(std::vector<int> {1, 2, 3});
    }

    return Err(ErrorCode::RuntimeError);
}


TEST_CASE("Error class", "[" NS "]")
{
    SECTION("Basic types - inline")
    {
        CHECK(Success(TestFunc1(42)));
        CHECK_FALSE(Success(TestFunc1(1)));
        CHECK(Failed(TestFunc1(1)));
        CHECK(Error(TestFunc1(1)) == ErrorCode::RuntimeError);
        CHECK(Value(TestFunc1(42)) == 1);
        CHECK_THROWS_AS(Value(TestFunc1(1)), std::bad_variant_access);
        CHECK(ValueOr(TestFunc1(1), 2) == 2);
    }

    SECTION("Basic types - reference")
    {
        auto ok  = TestFunc1(42);
        auto nok = TestFunc1(1);

        CHECK(Success(ok));
        CHECK_FALSE(Success(nok));
        CHECK(Failed(nok));
        CHECK(Error(nok) == ErrorCode::RuntimeError);
        CHECK_THROWS_AS(Value(std::move(nok)), std::bad_variant_access); // test using move
        CHECK(Value(ok) == 1);
        CHECK(ValueOr(nok, 2) == 2);
    }

    SECTION("Advanced types")
    {
        // simple test
        CHECK(Success(TestFunc2(42)));
        CHECK_FALSE(Success(TestFunc2(1)));
    }
}
