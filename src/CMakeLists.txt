cmake_minimum_required(VERSION 3.16)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_INTERPROCEDURAL_OPTIMIZATION TRUE)

project(pwn++ LANGUAGES CXX)

set(PROGNAME pwn++)
set(AUTHOR hugsy)
set(LICENSE MIT)


set_property(GLOBAL PROPERTY USE_FOLDERS ON)


option(DEBUG                  "Enable Debug"                                ON)
option(DISABLE_LOG_COLOR      "Disable ANSI color codes in log messages"    OFF)
option(INCLUDE_ASSEMBLER      "Compile with keystone-engine support"        ON)
option(INCLUDE_DISASSEMBLER   "Compile with capstone-engine support"        ON)
option(INCLUDE_BACKDOOR       "Enable the lua vm backdoor"                  OFF)


if(NOT INCLUDE_BACKDOOR)
    add_compile_definitions(PWN_NO_BACKDOOR)
endif()

# list(APPEND CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake")

#
# Build pwn++ library
#
add_subdirectory(pwn++)


#
# Build unit tests
#
add_subdirectory(tests)