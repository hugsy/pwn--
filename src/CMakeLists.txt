cmake_minimum_required(VERSION 3.17.0)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)
set(CMAKE_INTERPROCEDURAL_OPTIMIZATION TRUE)

project(pwn++ VERSION 0.1.0 LANGUAGES CXX)

set(PROGNAME pwn++)
set(AUTHOR hugsy)
set(LICENSE MIT)


set_property(GLOBAL PROPERTY USE_FOLDERS ON)


option(DEBUG                  "Enable Debug"                                ON)
option(DISABLE_LOG_COLOR      "Disable ANSI color codes in log messages"    OFF)
option(INCLUDE_ASSEMBLER      "Compile with keystone-engine support"        OFF)
option(INCLUDE_DISASSEMBLER   "Compile with capstone-engine support"        OFF)
option(INCLUDE_BACKDOOR       "Enable the lua vm backdoor"                  OFF)


if(NOT INCLUDE_BACKDOOR)
    add_compile_definitions(PWN_NO_BACKDOOR)
endif()


if(INCLUDE_ASSEMBLER)
    find_package(keystone CONFIG QUIET)
    target_link_libraries(pwn++ PRIVATE capstone.lib)
else()
    add_compile_definitions(PWN_NO_ASSEMBLER)
endif(INCLUDE_ASSEMBLER)


if(INCLUDE_DISASSEMBLER)
    find_package(capstone CONFIG QUIET)
    target_link_libraries(pwn++ PRIVATE capstone.lib)
else()
    add_compile_definitions(PWN_NO_DISASSEMBLER)
endif(INCLUDE_DISASSEMBLER)


#
# Build pwn++ library
#
add_subdirectory(pwn++)


#
# Build unit tests
#
add_subdirectory(tests)