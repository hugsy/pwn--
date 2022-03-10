cmake_minimum_required(VERSION 3.20)
set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED True)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_INTERPROCEDURAL_OPTIMIZATION True)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_LIST_DIR}/cmake")

project(
    pwn++
    LANGUAGES CXX
    VERSION 0.1.0
    DESCRIPTION "A (toy) Windows & Linux pwn library to play with modern C++."
    HOMEPAGE_URL https://github.com/hugsy/pwn--
)

set(PROJECT_AUTHOR hugsy)
set(PROJECT_LICENSE MIT)

set(CXX_STANDARD 23)

set_property(GLOBAL PROPERTY USE_FOLDERS ON)

option(DEBUG                       "Enable Debug"                                             ON)
option(DISABLE_LOG_COLOR           "Disable ANSI color codes in log messages"                 OFF)
option(INCLUDE_ASSEMBLER           "Compile with assembler support"                           OFF)
option(INCLUDE_DISASSEMBLER        "Compile with disassembler support"                        ON)
option(BUILD_TOOLKIT               "Compile the executables of pwn++ toolkit"                 ON)
option(BUILD_TESTING               "Compile the test suite"                                   ON)


set(PWNLIB_ROOT_DIR ${CMAKE_CURRENT_LIST_DIR})


if(INCLUDE_ASSEMBLER)
    option(DEBUG "" ${DEBUG})
    option(BUILD_TESTING "" OFF)
    option(BUILD_TOOLKIT "" OFF)
    add_subdirectory(${PWNLIB_ROOT_DIR}/deps/asm++)
endif()


if(INCLUDE_DISASSEMBLER)
    option(ZYDIS_BUILD_TOOLS "" OFF)
    option(ZYDIS_BUILD_EXAMPLES "" OFF)
    option(ZYDIS_BUILD_SHARED_LIB "" OFF)
    add_subdirectory(${PWNLIB_ROOT_DIR}/deps/zydis)
endif()


#
# Build library
#
add_subdirectory(src)


#
# Build unit tests
#
if(BUILD_TESTING)
    include(CTest)
    add_subdirectory(tests)
endif()


#
# Build toolkit
#
if(BUILD_TOOLKIT)
    add_subdirectory(tools)
endif()
