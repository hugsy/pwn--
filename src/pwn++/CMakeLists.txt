project(pwn++ LANGUAGES CXX VERSION 0.1.3)

set(PWNLIB_SRC_LIB_DIR ${PWNLIB_SRC_DIR}/pwn++ CACHE INTERNAL "PWNLIB_SRC_LIB_DIR")
set(PWNLIB_SRC_HDR_DIR ${PWNLIB_SRC_DIR}/inc CACHE INTERNAL "PWNLIB_SRC_HDR_DIR")

#
# Set up the variables exported to constants.hpp
#
set(PWN_LIBRARY_NAME ${PROJECT_NAME})
set(PWN_LIBRARY_AUTHOR ${PROJECT_AUTHOR})
set(PWN_LIBRARY_LICENSE ${PROJECT_LICENSE})
set(PWN_LIBRARY_VERSION_MAJOR ${PROJECT_VERSION_MAJOR})
set(PWN_LIBRARY_VERSION_MINOR ${PROJECT_VERSION_MINOR})
set(PWN_LIBRARY_VERSION_PATCH ${PROJECT_VERSION_PATCH})
set(PWN_LIBRARY_VERSION_RELEASE "Standalone")
set(PWN_LIBRARY_VERSION ${PROJECT_VERSION})
set(PWN_BUILD_ARCHITECTURE ${CMAKE_SYSTEM_PROCESSOR})
set(PWN_BUILD_OS ${CMAKE_SYSTEM_NAME})

set(PWN_HAS_ASSEMBLER ${PWN_INCLUDE_ASSEMBLER})
set(PWN_HAS_DISASSEMBLER ${PWN_INCLUDE_DISASSEMBLER})
set(PWN_USE_BACKDOOR ${PWN_ENABLE_LUA_BACKDOOR})

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

    set(PWN_LIBRARY_VERSION_RELEASE "${GIT_RELEASE_BRANCH}:${GIT_RELEASE_COMMIT}")
endif()

#
# Collect all common source files
#
set(COMMON_SOURCE_DIR ${PWNLIB_SRC_LIB_DIR})
set(
    COMMON_SOURCE_FILES

    ${COMMON_SOURCE_DIR}/asm.cpp
    ${COMMON_SOURCE_DIR}/architecture.cpp
    ${COMMON_SOURCE_DIR}/context.cpp
    ${COMMON_SOURCE_DIR}/crypto.cpp
    ${COMMON_SOURCE_DIR}/error.cpp
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
    ${COMMON_HEADER_DIR}/constants.hpp.in
    ${COMMON_HEADER_DIR}/constants.hpp
    NEWLINE_STYLE WIN32
)

#
# Collect all common source header files
#
set(
    COMMON_HEADER_FILES

    ${COMMON_HEADER_DIR}/pwn_export.hpp
    ${COMMON_HEADER_DIR}/architecture.hpp
    ${COMMON_HEADER_DIR}/asm.hpp
    ${COMMON_HEADER_DIR}/common.hpp
    ${COMMON_HEADER_DIR}/constants.hpp
    ${COMMON_HEADER_DIR}/crypto.hpp
    ${COMMON_HEADER_DIR}/disasm.hpp
    ${COMMON_HEADER_DIR}/log.hpp
    ${COMMON_HEADER_DIR}/handle.hpp
    ${COMMON_HEADER_DIR}/tube.hpp
    ${COMMON_HEADER_DIR}/utils.hpp
    ${COMMON_HEADER_DIR}/error.hpp
)

if(PWN_ENABLE_LUA_BACKDOOR)
    set(COMMON_HEADER_FILES ${COMMON_HEADER_FILES} ${COMMON_HEADER_DIR}/backdoor.hpp)
endif(PWN_ENABLE_LUA_BACKDOOR)

#
# Create the target
#
add_library(${PROJECT_NAME} STATIC)

target_precompile_headers(${PROJECT_NAME} PRIVATE ${PWNLIB_SRC_HDR_DIR}/pch.hpp)
target_compile_features(${PROJECT_NAME} PRIVATE cxx_std_20)
target_include_directories(${PROJECT_NAME} PUBLIC ${COMMON_HEADER_DIR})

#
# Print out cmake compile info
#
message(STATUS "PWN_LOG_USE_COLOR                      ${PWN_LOG_USE_COLOR}")
message(STATUS "PWN_INCLUDE_ASSEMBLER                  ${PWN_INCLUDE_ASSEMBLER}")
message(STATUS "PWN_INCLUDE_DISASSEMBLER               ${PWN_INCLUDE_DISASSEMBLER}")
message(STATUS "PWN_BUILD_TOOLKIT                      ${PWN_BUILD_TOOLKIT}")
message(STATUS "PWN_BUILD_TESTING                      ${PWN_BUILD_TESTING}")
message(STATUS "PWN_ENABLE_LUA_BACKDOOR                ${PWN_ENABLE_LUA_BACKDOOR}")

target_compile_definitions(${PROJECT_NAME} PRIVATE $<$<CONFIG:Debug>:_DEBUG DEBUG>)

if(PWN_INCLUDE_DISASSEMBLER)
    target_link_libraries(${PROJECT_NAME} PRIVATE Zydis)
    target_include_directories(${PROJECT_NAME} PRIVATE ${PWNLIB_ROOT_DIR}/deps/zydis/include)
endif()

if(PWN_INCLUDE_ASSEMBLER)
    # TODO: use asm++ when ready
endif()

if(PWN_ENABLE_LUA_BACKDOOR)
    target_link_libraries(${PROJECT_NAME} PRIVATE lua::lib)
    target_include_directories(${PROJECT_NAME} PRIVATE ${PWNLIB_ROOT_DIR}/deps/lua/include)
endif()

target_include_directories(${PROJECT_NAME} PRIVATE ${PWNLIB_ROOT_DIR}/deps/phnt)
target_compile_definitions(${PROJECT_NAME} PRIVATE PHNT_VERSION=PHNT_20H2)

#
# Generate the build export header from cmake
#
include(GenerateExportHeader)

generate_export_header(
    ${PROJECT_NAME}
    BASE_NAME ${PROJECT_NAME}
    EXPORT_FILE_NAME ${COMMON_HEADER_DIR}/pwn_export.hpp
    STATIC_DEFINE pwn_built_as_static
    EXPORT_MACRO_NAME PWNAPI
    NO_EXPORT_MACRO_NAME PWN_NO_EXPORT
    DEPRECATED_MACRO_NAME PWN_DEPRECATED
)

target_sources(
    ${PROJECT_NAME}
    PUBLIC ${COMMON_HEADER_FILES}
    PRIVATE ${COMMON_SOURCE_FILES}
)

target_include_directories(
    ${PROJECT_NAME}
    PUBLIC ${COMMON_HEADER_DIR}
)

#
# Defines the OS-specific sources & compiler flags
#
if(WIN32)
    add_subdirectory(win32)
else()
    add_subdirectory(linux)
endif(WIN32)

#
# Installation directives
#
install(TARGETS ${PROJECT_NAME} DESTINATION lib)
install(FILES $<TARGET_PROPERTY:${PROJECT_NAME},INTERFACE_SOURCES> DESTINATION include/${PROJECT_NAME})
