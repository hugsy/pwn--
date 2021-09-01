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
option(INCLUDE_ASSEMBLER      "Compile with keystone-engine support"        OFF)
option(INCLUDE_DISASSEMBLER   "Compile with capstone-engine support"        OFF)
option(INCLUDE_BACKDOOR       "Enable the lua vm backdoor"                  OFF)
option(BUILD_TOOLKIT          "Compile the standalone exes"                 ON)


#
# Build library
#
add_subdirectory(src)


#
# Build toolkit
#
add_subdirectory(tools)