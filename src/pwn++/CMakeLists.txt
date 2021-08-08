option(DEBUG                  "Enable Debug"                                ON)
option(DISABLE_LOG_COLOR      "Disable ANSI color codes in log messages"    OFF)
option(INCLUDE_ASSEMBLER      "Compile with keystone-engine support"        OFF)
option(INCLUDE_DISASSEMBLER   "Compile with capstone-engine support"        OFF)
option(INCLUDE_BACKDOOR       "Enable the lua vm backdoor"                  OFF)


if(MSVC)
    add_compile_options(/W3 /WX)
else()
    add_compile_options(-W -Wall -Werror)
endif(MSVC)


include (GenerateExportHeader)



set(COMMON_SOURCE_DIR ${CMAKE_CURRENT_LIST_DIR}/../pwn++)
set(
    COMMON_SOURCE_FILES
    ${COMMON_SOURCE_DIR}/log.cpp
    ${COMMON_SOURCE_DIR}/pwn.cpp
    ${COMMON_SOURCE_DIR}/context.cpp
    ${COMMON_SOURCE_DIR}/utils.cpp
)


set(COMMON_HEADER_DIR ${CMAKE_CURRENT_LIST_DIR}/../inc)
set(
    COMMON_HEADER_FILES
    ${COMMON_HEADER_DIR}/constants.hpp
    ${COMMON_HEADER_DIR}/common.hpp
    ${COMMON_HEADER_DIR}/utils.hpp
    ${COMMON_HEADER_DIR}/handle.hpp
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

add_compile_definitions(
    PROGNAME=\"${PROGNAME}\"
    AUTHOR=\"${AUTHOR}\"
    LICENSE=\"${LICENSE}\"
    PWN_VERSION_MAJOR=${PWN_VERSION_MAJOR}
    PWN_VERSION_MINOR=${PWN_VERSION_MINOR}
    PWN_VERSION_STR=\"${PWN_VERSION_STR}\"
)


if (WIN32)
    add_subdirectory(win)
else()
    add_subdirectory(linux)
endif(WIN32)

