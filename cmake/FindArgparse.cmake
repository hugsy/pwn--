include(FetchContent)

FetchContent_Declare(
    Deps_Argparse
    URL https://github.com/p-ranav/argparse/archive/refs/tags/v3.0.zip
    URL_HASH MD5=a44c0401238e87239e31652b72fded20
)

FetchContent_MakeAvailable(Deps_Argparse)
