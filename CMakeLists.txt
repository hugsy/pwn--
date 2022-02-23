cmake_minimum_required(VERSION 3.16)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_INTERPROCEDURAL_OPTIMIZATION TRUE)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_LIST_DIR}/cmake")

project(pwn++ LANGUAGES CXX)

set(PROGNAME pwn++)
set(AUTHOR hugsy)
set(LICENSE MIT)

set_property(GLOBAL PROPERTY USE_FOLDERS ON)

option(DEBUG                       "Enable Debug"                                             ON)
option(DISABLE_LOG_COLOR           "Disable ANSI color codes in log messages"                 OFF)
option(INCLUDE_ASSEMBLER           "Compile with assembler support"                           OFF)
option(INCLUDE_DISASSEMBLER        "Compile with disassembler support"                        ON)
option(INCLUDE_BACKDOOR            "Enable the lua vm backdoor"                               OFF)
option(BUILD_TOOLKIT               "Compile the executables of pwn++ toolkit"                 ON)

set(PWNLIB_ROOT_DIR ${CMAKE_CURRENT_LIST_DIR})

if(INCLUDE_ASSEMBLER)
    add_subdirectory(${PWNLIB_ROOT_DIR}/deps/AssemblyLine)
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
# Build toolkit
#
add_subdirectory(tools)
