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
    ${HEADER_DIR}/cpu.hpp
    ${HEADER_DIR}/registry.hpp
    ${HEADER_DIR}/kernel.hpp
    ${HEADER_DIR}/job.hpp
)

set(SOURCE_DIR ${COMMON_SOURCE_DIR}/win)
set(
    SOURCE_FILES
    ${COMMON_SOURCE_FILES}
    ${SOURCE_DIR}/dllmain.cpp
    ${SOURCE_DIR}/system.cpp
    ${SOURCE_DIR}/process.cpp
    ${SOURCE_DIR}/thread.cpp
    ${SOURCE_DIR}/cpu.cpp
    ${SOURCE_DIR}/kernel.cpp
    ${SOURCE_DIR}/job.cpp
)


add_library(pwn++ SHARED ${SOURCE_FILES})

# if(DEBUG)
#     target_compile_options(pwn++ PRIVATE /MTd)
# else()
#     target_compile_options(pwn++ PRIVATE /MT)
# endif(DEBUG)

add_compile_options(/W3 /WX /Wall)
# add_compile_options(/W3 /WX /Wall /sdl /guard:cf /guard:ehcont /CETCOMPAT)

# TODO: use proper vcpkg envvar way
set(VCPKG_ROOT "C:\\tools\\vcpkg\\installed")

if(INCLUDE_ASSEMBLER)
    # find_package(keystone-static REQUIRED)
    set(KS_INCLUDE_DIR "${VCPKG_ROOT}\\x64-windows-static\\include\\")
    if(DEBUG)
        target_link_libraries(pwn++ PRIVATE "${VCPKG_ROOT}\\x64-windows-static\\debug\\lib\\keystone.lib")
    else()
        target_link_libraries(pwn++ PRIVATE "${VCPKG_ROOT}\\x64-windows-static\\lib\\keystone.lib")
    endif(DEBUG)
else()
    add_compile_definitions(PWN_NO_ASSEMBLER)
endif(INCLUDE_ASSEMBLER)


if(INCLUDE_DISASSEMBLER)
    # find_package(capstone-static REQUIRED)
    set(CS_INCLUDE_DIR "${VCPKG_ROOT}\\x64-windows-static\\include\\")
    if(DEBUG)
        target_link_libraries(pwn++ PRIVATE "${VCPKG_ROOT}\\x64-windows-static\\debug\\lib\\capstone.lib")
    else()
        target_link_libraries(pwn++ PRIVATE "${VCPKG_ROOT}\\x64-windows-static\\lib\\capstone.lib")
    endif(DEBUG)
else()
    add_compile_definitions(PWN_NO_DISASSEMBLER)
endif(INCLUDE_DISASSEMBLER)

target_precompile_headers(pwn++ PRIVATE ${HEADER_DIR}/pch.hpp)

target_compile_options(pwn++ PRIVATE "$<$<COMPILE_LANGUAGE:CXX>:/Zc:__cplusplus>")
target_compile_features(pwn++ PRIVATE cxx_std_17)

target_include_directories(pwn++ PUBLIC ${COMMON_HEADER_DIR} ${HEADER_DIR})
target_include_directories(pwn++ PRIVATE ${COMMON_SOURCE_DIR} ${SOURCE_DIR} ${KS_INCLUDE_DIR})

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
