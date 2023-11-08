include(FetchContent)

FetchContent_Declare(
    Deps_Argparse
    URL https://github.com/p-ranav/argparse/archive/refs/tags/v3.0.zip
    URL_HASH MD5=a44c0401238e87239e31652b72fded20
)

FetchContent_MakeAvailable(Deps_Argparse)

message(STATUS "Using ArgParse in '${deps_argparse_SOURCE_DIR}'")

add_library(Deps_ArgParse INTERFACE EXCLUDE_FROM_ALL)
target_compile_features(Deps_ArgParse INTERFACE cxx_std_17)
target_include_directories(Deps_ArgParse INTERFACE ${deps_argparse_SOURCE_DIR}/include)
