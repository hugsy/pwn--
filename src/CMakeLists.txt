cmake_minimum_required(VERSION 3.17.0)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)
set(CMAKE_INTERPROCEDURAL_OPTIMIZATION TRUE)

project(pwn++ VERSION 0.1.0 LANGUAGES CXX)

set(PROGNAME pwn++)
set(AUTHOR hugsy)
set(LICENSE MIT)


set_property(GLOBAL PROPERTY USE_FOLDERS ON)


#
# Build pwn++ library
#
add_subdirectory(pwn++)


#
# Build unit tests
#
add_subdirectory(tests)