set(PWNLIB_SRC_LIB_DIR ${PWNLIB_SRC_DIR}/pwn++ CACHE INTERNAL "PWNLIB_SRC_LIB_DIR")
set(PWNLIB_SRC_HDR_DIR ${PWNLIB_SRC_DIR}/inc CACHE INTERNAL "PWNLIB_SRC_HDR_DIR")


#
# If `git` is found, declare the branch/commit hash for debugging
#
find_package(Git)
if(Git_FOUND)
    execute_process(
        COMMAND ${GIT_EXECUTABLE} rev-parse --abbrev-ref HEAD
        OUTPUT_VARIABLE GIT_RELEASE_BRANCH
        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
    )
    execute_process(
        COMMAND ${GIT_EXECUTABLE} log -n 1 --pretty=format:%t
        OUTPUT_VARIABLE GIT_RELEASE_COMMIT
        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
    )

    string(STRIP "${GIT_RELEASE_BRANCH}" GIT_RELEASE_BRANCH)
    string(STRIP "${GIT_RELEASE_COMMIT}" GIT_RELEASE_COMMIT)

    set (PWN_VERSION_REL "${GIT_RELEASE_BRANCH}:${GIT_RELEASE_COMMIT}")
endif()


#
# Collect all common source files
#
set(COMMON_SOURCE_DIR ${PWNLIB_SRC_LIB_DIR})
set(
    COMMON_SOURCE_FILES

    ${COMMON_SOURCE_DIR}/asm.cpp
    ${COMMON_SOURCE_DIR}/context.cpp
    ${COMMON_SOURCE_DIR}/crypto.cpp
    ${COMMON_SOURCE_DIR}/disasm.cpp
    ${COMMON_SOURCE_DIR}/log.cpp
    ${COMMON_SOURCE_DIR}/pwn.cpp
    ${COMMON_SOURCE_DIR}/tube.cpp
    ${COMMON_SOURCE_DIR}/utils.cpp
)


set(COMMON_HEADER_DIR ${PWNLIB_SRC_HDR_DIR})


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

    ${COMMON_HEADER_DIR}/pch.hpp
    ${COMMON_HEADER_DIR}/pwn_export.hpp

    ${COMMON_HEADER_DIR}/asm.hpp
    ${COMMON_HEADER_DIR}/common.hpp
    ${COMMON_HEADER_DIR}/constants.hpp
    ${COMMON_HEADER_DIR}/crypto.hpp
    ${COMMON_HEADER_DIR}/disasm.hpp
    ${COMMON_HEADER_DIR}/log.hpp
    ${COMMON_HEADER_DIR}/handle.hpp
    ${COMMON_HEADER_DIR}/tube.hpp
    ${COMMON_HEADER_DIR}/utils.hpp
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


if(NOT INCLUDE_DISASSEMBLER)
    add_compile_definitions(PWN_NO_DISASSEMBLER)
endif()


if(NOT INCLUDE_ASSEMBLER)
    add_compile_definitions(PWN_NO_ASSEMBLER)
endif()


if (WIN32)
    add_subdirectory(win32)
else()
    add_subdirectory(linux)
endif(WIN32)

