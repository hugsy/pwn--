cmake_minimum_required(VERSION 3.17.0)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)
set(CMAKE_INTERPROCEDURAL_OPTIMIZATION TRUE)

project(pwn++ VERSION 0.1.0 LANGUAGES C CXX)

set(PROGNAME pwn++)
set(AUTHOR hugsy)
set(LICENSE MIT)

if(MSVC)
    add_compile_definitions(/W3 /WX)
else()
    add_compile_definitions(-W -Wall -Werror)
endif(MSVC)

set_property(GLOBAL PROPERTY USE_FOLDERS ON)

add_subdirectory(pwn++)