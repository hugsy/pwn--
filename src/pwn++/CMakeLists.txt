cmake_minimum_required(VERSION 3.20.0)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)
set(CMAKE_INTERPROCEDURAL_OPTIMIZATION TRUE)

option(DEBUG                  "Enable Debug"                                ON)
option(DISABLE_LOG_COLOR      "Disable ANSI color codes in log messages"    OFF)
option(INCLUDE_ASSEMBLER      "Compile with keystone-engine support"        OFF)
option(INCLUDE_DISASSEMBLER   "Compile with capstone-engine support"        OFF)
option(INCLUDE_BACKDOOR       "Enable the lua vm backdoor"                  OFF)


include (GenerateExportHeader)



set(COMMON_SOURCE_DIR ../pwn++)
set(
    COMMON_SOURCE_FILES
    ${COMMON_SOURCE_DIR}/log.cpp
    ${COMMON_SOURCE_DIR}/pwn.cpp
    ${COMMON_SOURCE_DIR}/context.cpp
    ${COMMON_SOURCE_DIR}/utils.cpp
)

set(COMMON_HEADER_DIR ../inc)
set(
    COMMON_HEADER_FILES
    ${COMMON_HEADER_DIR}/constants.hpp
    ${COMMON_HEADER_DIR}/common.hpp
    ${COMMON_HEADER_DIR}/utils.hpp
)


set (PWN_VERSION_MAJOR 0)
set (PWN_VERSION_MINOR 1)
set (PWN_VERSION_STR "${PWN_VERSION_MAJOR}.${PWN_VERSION_MINOR}")

find_program(GIT_EXECUTABLE NAMES git)

if(GIT_EXECUTABLE)
    execute_process(
        COMMAND ${GIT_EXECUTABLE} rev-parse --abbrev-ref HEAD
        OUTPUT_VARIABLE GIT_RELEASE_BRANCH
        WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
    )
    execute_process(
        COMMAND ${GIT_EXECUTABLE} log -n 1 --pretty=format:%t
        OUTPUT_VARIABLE GIT_RELEASE_COMMIT
        WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
    )

    string(STRIP "${GIT_RELEASE_BRANCH}" GIT_RELEASE_BRANCH)
    string(STRIP "${GIT_RELEASE_COMMIT}" GIT_RELEASE_COMMIT)

    if(NOT GIT_RELEASE_BRANCH STREQUAL "master")
        set (PWN_VERSION_REL "${GIT_RELEASE_BRANCH}:${GIT_RELEASE_COMMIT}")
        set (PWN_VERSION_STR "${PWN_VERSION_MAJOR}.${PWN_VERSION_MINOR}-${PWN_VERSION_REL}")
    endif()

endif(GIT_EXECUTABLE)

add_compile_definitions(PROGNAME)
add_compile_definitions(AUTHOR)
add_compile_definitions(LICENSE)
add_compile_definitions(PWN_VERSION_MAJOR)
add_compile_definitions(PWN_VERSION_MINOR)
add_compile_definitions(PWN_VERSION_STR)


#
# for now only suport windows build
#
if (WIN32)

set(HEADER_DIR ${COMMON_HEADER_DIR}/win)
set(
    HEADER_FILES
    ${COMMON_HEADER_FILES}
    ${HEADER_DIR}/framework.hpp
)

set(SOURCE_DIR ${COMMON_SOURCE_DIR}/win)
set(
    SOURCE_FILES
    ${COMMON_SOURCE_FILES}
    ${SOURCE_DIR}/dllmain.cpp
)

add_library(pwn++ SHARED ${SOURCE_FILES})

target_precompile_headers(pwn++ PRIVATE ${HEADER_DIR}/pch.hpp)

target_compile_options(pwn++ PRIVATE "$<$<COMPILE_LANGUAGE:CXX>:/Zc:__cplusplus>")

target_include_directories(pwn++ PUBLIC ${COMMON_HEADER_DIR} ${HEADER_DIR})
target_include_directories(pwn++ PRIVATE ${COMMON_SOURCE_DIR} ${SOURCE_DIR})

target_sources(pwn++ PRIVATE ${SOURCE_FILES})

GENERATE_EXPORT_HEADER(
    pwn++
    BASE_NAME pwn++
    EXPORT_MACRO_NAME PWN_EXPORT
    EXPORT_FILE_NAME pwn_export.hpp
    STATIC_DEFINE pwn_built_as_static
)

add_compile_definitions(_UNICODE)
add_compile_definitions(UNICODE)


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



target_link_libraries(
    pwn++
    PRIVATE
    ws2_32.lib
    userenv.lib
    kernel32.lib
    user32.lib
    Rpcrt4.lib
    ntdll.lib
)


else()

# Linux definitions

set(HEADER_DIR ${COMMON_HEADER_DIR}/linux)
set(
    HEADER_FILES
    ${COMMON_HEADER_FILES}
    # ${HEADER_DIR}/process.hpp
)

set(SOURCE_DIR ${COMMON_SOURCE_DIR}/linux)
set(
    SOURCE_FILES
    ${COMMON_SOURCE_FILES}
    # ${SOURCE_DIR}/process.cpp
)

add_library(pwn++ SHARED ${SOURCE_FILES})

target_include_directories(pwn++ PUBLIC ../inc/linux)
target_include_directories(pwn++ PRIVATE ../src/linux)


endif(WIN32)