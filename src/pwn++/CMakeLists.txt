set (PWN_VERSION_MAJOR 0)
set (PWN_VERSION_MINOR 1)
set (PWN_VERSION_STR "${PWN_VERSION_MAJOR}.${PWN_VERSION_MINOR}")

include (GenerateExportHeader)

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


#
# Collect all common source files
#
set(COMMON_SOURCE_DIR ${CMAKE_CURRENT_LIST_DIR}/../pwn++)
set(
    COMMON_SOURCE_FILES
    ${COMMON_SOURCE_DIR}/log.cpp
    ${COMMON_SOURCE_DIR}/pwn.cpp
    ${COMMON_SOURCE_DIR}/context.cpp
    ${COMMON_SOURCE_DIR}/utils.cpp
    ${COMMON_SOURCE_DIR}/crypto.cpp
    ${COMMON_SOURCE_DIR}/asm.cpp
    ${COMMON_SOURCE_DIR}/disasm.cpp
    ${COMMON_SOURCE_DIR}/tube.cpp
)


set(COMMON_HEADER_DIR ${CMAKE_CURRENT_LIST_DIR}/../inc)


#
# Create the constants.hpp macro file
#
configure_file(
    "${COMMON_HEADER_DIR}/constants.hpp.in"
    "${COMMON_HEADER_DIR}/constants.hpp"
    NEWLINE_STYLE WIN32
)


#
# Collect all common source files
#
set(
    COMMON_HEADER_FILES
    ${COMMON_HEADER_DIR}/constants.hpp
    ${COMMON_HEADER_DIR}/common.hpp
    ${COMMON_HEADER_DIR}/utils.hpp
    ${COMMON_HEADER_DIR}/handle.hpp
    ${COMMON_HEADER_DIR}/crypto.hpp
    ${COMMON_HEADER_DIR}/asm.hpp
    ${COMMON_HEADER_DIR}/disasm.hpp
    ${COMMON_HEADER_DIR}/tube.hpp
)



#
# Print out cmake compile info
#
message(STATUS "CMAKE_MODULE_PATH:                 ${CMAKE_MODULE_PATH}")
message(STATUS "CMAKE_CXX_LINK_EXECUTABLE:         ${CMAKE_CXX_LINK_EXECUTABLE}")
message(STATUS "CMAKE_CXX_LINK_FLAGS:              ${CMAKE_CXX_LINK_FLAGS}")
message(STATUS "CMAKE_EXE_LINKER_FLAGS:            ${CMAKE_EXE_LINKER_FLAGS}")
message(STATUS "CMAKE_EXE_LINKER_FLAGS_RELEASE:    ${CMAKE_EXE_LINKER_FLAGS_RELEASE}")
message(STATUS "CMAKE_SHARED_LINKER_FLAGS:         ${CMAKE_SHARED_LINKER_FLAGS}")
message(STATUS "CMAKE_SHARED_LINKER_FLAGS_RELEASE: ${CMAKE_SHARED_LINKER_FLAGS_RELEASE}")
message(STATUS "CMAKE_SYSTEM_PROCESSOR:            ${CMAKE_SYSTEM_PROCESSOR}")
message(STATUS "CMAKE_SYSTEM_NAME:                 ${CMAKE_SYSTEM_NAME}")

message(STATUS "INCLUDE_ASSEMBLER:                 ${INCLUDE_ASSEMBLER}")
message(STATUS "INCLUDE_DISASSEMBLER:              ${INCLUDE_DISASSEMBLER}")
message(STATUS "DEBUG:                             ${DEBUG}")

if (WIN32)
    add_subdirectory(win)
else()
    add_subdirectory(linux)
endif(WIN32)

