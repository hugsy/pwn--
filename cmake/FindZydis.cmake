#
# Use the Amalgated releasse version of Zydis
#
include(FetchContent)

FetchContent_Declare(
    Deps_Zydis
    URL https://github.com/zyantific/zydis/releases/download/v4.0.0/zydis-amalgamated.zip
    URL_HASH MD5=953774e42dee260ed34db1fb576092d3
)
FetchContent_MakeAvailable(Deps_Zydis)

message(STATUS "Using Zydis in '${deps_zydis_SOURCE_DIR}'")

add_library(Deps_Zydis STATIC ${deps_zydis_SOURCE_DIR}/Zydis.c)
add_library(PWN::Deps::Zydis ALIAS Deps_Zydis)
target_compile_definitions(Deps_Zydis PUBLIC ZYDIS_STATIC_BUILD=1)
target_include_directories(Deps_Zydis PUBLIC ${deps_zydis_SOURCE_DIR})
