cmake_minimum_required(VERSION 3.20)
set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED True)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_INTERPROCEDURAL_OPTIMIZATION True)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_LIST_DIR}/cmake")

project(
    pwn++
    DESCRIPTION "A (toy) Windows & Linux pwn library to play with modern C++."
    HOMEPAGE_URL https://github.com/hugsy/pwn--
)

set(PROJECT_AUTHOR hugsy)
set(PROJECT_LICENSE MIT)

set(CXX_STANDARD 23)

set_property(GLOBAL PROPERTY USE_FOLDERS ON)

option(DEBUG                           "Enable Debug"                                             OFF)
option(PWN_LOG_USE_COLOR               "Use ANSI color codes in log messages"                     OFF)
option(PWN_INCLUDE_ASSEMBLER           "Compile with assembler support"                           OFF)
option(PWN_INCLUDE_DISASSEMBLER        "Compile with disassembler support"                        ON)
option(PWN_BUILD_TOOLKIT               "Compile the executables of pwn++ toolkit"                 ON)
option(PWN_BUILD_TESTING               "Compile the test suite"                                   ON)
option(PWN_ENABLE_LUA_BACKDOOR         "Enable Lua scripting for backdoor"                        ON)


set(PWNLIB_ROOT_DIR ${CMAKE_CURRENT_LIST_DIR})


if(PWN_INCLUDE_ASSEMBLER)
    option(DEBUG "" ${DEBUG})
    option(BUILD_TESTING "" OFF)
    option(BUILD_TOOLKIT "" OFF)
    add_subdirectory(${PWNLIB_ROOT_DIR}/deps/asm++)
endif()


if(PWN_INCLUDE_DISASSEMBLER)
    option(ZYDIS_BUILD_TOOLS "" OFF)
    option(ZYDIS_BUILD_EXAMPLES "" OFF)
    option(ZYDIS_BUILD_SHARED_LIB "" OFF)
    add_subdirectory(${PWNLIB_ROOT_DIR}/deps/zydis)
endif()

if(PWN_ENABLE_LUA_BACKDOOR)
    option(BUILD_SHARED_LIBS "" OFF)
    add_subdirectory(${PWNLIB_ROOT_DIR}/deps/lua)
endif()

#
# Build library
#
add_subdirectory(src)


#
# Build unit tests
#
if(PWN_BUILD_TESTING)
    include(CTest)
    add_subdirectory(tests)
endif()


#
# Build toolkit
#
if(PWN_BUILD_TOOLKIT)
    add_subdirectory(tools)
endif()
