#define CATCH_CONFIG_MAIN
#define CATCH_CONFIG_ENABLE_BENCHMARKING

#include <catch.hpp>

#include "Common.hpp"

Result<int>
TestFunc11(uint32_t i)
{
    if ( i == 42 )
    {
        return Ok(1);
    }

    return Err(ErrorCode::RuntimeError);
}

int
TestFunc12(uint32_t i)
{
    if ( i == 42 )
    {
        return 1;
    }

    return -1;
}


Result<std::vector<int>>
TestFunc21(uint32_t i)
{
    if ( i == 42 )
    {
        return Ok(std::move(std::vector<int> {1, 2, 3}));
    }

    return Err(ErrorCode::RuntimeError);
}

std::vector<int>
TestFunc22(uint32_t i)
{
    if ( i == 42 )
    {
        return std::vector<int> {1, 2, 3};
    }

    return std::vector<int> {};
}


TEST_CASE("Simple perf checks", "Benchmarks::Error")
{
    BENCHMARK("[managed] basic return type - success")
    {
        return std::move(TestFunc11(42));
    };

    BENCHMARK("[unmanaged] basic return type - success")
    {
        return TestFunc12(42); // prevent optimization
    };

    BENCHMARK("[managed] basic return type - failure")
    {
        return std::move(TestFunc11(1));
    };

    BENCHMARK("[unmanaged] basic return type - failure")
    {
        return TestFunc12(1);
    };
}
