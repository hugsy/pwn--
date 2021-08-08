#
# Windows (msvc) specific definitions
#

set(HEADER_DIR ${COMMON_HEADER_DIR}/win)
set(
    HEADER_FILES
    ${COMMON_HEADER_FILES}
    ${HEADER_DIR}/framework.hpp
    ${HEADER_DIR}/system.hpp
    ${HEADER_DIR}/process.hpp
    ${HEADER_DIR}/thread.hpp
)

set(SOURCE_DIR ${COMMON_SOURCE_DIR}/win)
set(
    SOURCE_FILES
    ${COMMON_SOURCE_FILES}
    ${SOURCE_DIR}/dllmain.cpp
    ${SOURCE_DIR}/system.cpp
    ${SOURCE_DIR}/process.cpp
    ${SOURCE_DIR}/thread.cpp
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
