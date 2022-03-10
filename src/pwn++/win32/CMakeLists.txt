#
# Windows (msvc) specific definitions
#

set(HEADER_DIR ${PWNLIB_SRC_HDR_DIR}/win32)
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
    ${HEADER_DIR}/backdoor.hpp

    ${HEADER_DIR}/ctf/remote.hpp
)

set(SOURCE_DIR ${PWNLIB_SRC_LIB_DIR}/win32)
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
    ${SOURCE_DIR}/backdoor.cpp

    ${SOURCE_DIR}/ctf/remote.cpp
)


add_library(${CMAKE_PROJECT_NAME} SHARED ${SOURCE_FILES})

set(CMAKE_SHARED_LINKER_FLAGS "/DEBUG:FULL /WX /RELEASE /SUBSYSTEM:Console /MANIFEST:NO /DLL /profile /guard:cf /DEBUGTYPE:cv,fixup /LARGEADDRESSAWARE")
add_compile_options(/std:c++latest /W3 /WX /Wall /CETCOMPAT /diagnostics:caret /W4 /WX  /d1FastFail /guard:cf /Z7 /Gm- /Gy /Zp8 /permissive- /Zl /ZH:SHA_256)


if(INCLUDE_ASSEMBLER)
    # target_link_libraries(${CMAKE_PROJECT_NAME} PRIVATE asmlib)
# else()
    add_compile_definitions(PWN_NO_ASSEMBLER)
endif(INCLUDE_ASSEMBLER)


if(INCLUDE_DISASSEMBLER)
    target_link_libraries(${CMAKE_PROJECT_NAME} PRIVATE Zydis)
    set(ZYDIS_INCLUDE_DIR ${PWNLIB_ROOT_DIR}/deps/zydis/include)
    set(EXTRA_HEADER_DIR ${ZYDIS_INCLUDE_DIR})
else()
    add_compile_definitions(PWN_NO_DISASSEMBLER)
endif(INCLUDE_DISASSEMBLER)


target_precompile_headers(${CMAKE_PROJECT_NAME} PRIVATE ${PWNLIB_SRC_HDR_DIR}/pch.hpp)

target_compile_features(${CMAKE_PROJECT_NAME} PRIVATE cxx_std_20)
target_compile_options(${CMAKE_PROJECT_NAME} PRIVATE "$<$<COMPILE_LANGUAGE:CXX>:/Zc:__cplusplus>")

target_include_directories(${CMAKE_PROJECT_NAME} PUBLIC ${COMMON_HEADER_DIR} ${HEADER_DIR})
target_include_directories(${CMAKE_PROJECT_NAME} PRIVATE ${COMMON_SOURCE_DIR} ${SOURCE_DIR} ${EXTRA_HEADER_DIR})

target_sources(${CMAKE_PROJECT_NAME} PRIVATE ${SOURCE_FILES})


#
# Generate the build export header from cmake
#
include(GenerateExportHeader)

generate_export_header(
    ${CMAKE_PROJECT_NAME}
    BASE_NAME ${CMAKE_PROJECT_NAME}
    EXPORT_FILE_NAME ${COMMON_HEADER_DIR}/pwn_export.hpp
    STATIC_DEFINE pwn_built_as_static
    EXPORT_MACRO_NAME PWNAPI
    NO_EXPORT_MACRO_NAME PWN_NO_EXPORT
    DEPRECATED_MACRO_NAME PWN_DEPRECATED
)

add_compile_definitions(_UNICODE UNICODE)

target_link_libraries(
    ${CMAKE_PROJECT_NAME}

    PRIVATE
    ws2_32.lib
    userenv.lib
    kernel32.lib
    user32.lib
    Rpcrt4.lib
    ntdll.lib
)


#
# Installation directives
#
install(TARGETS ${CMAKE_PROJECT_NAME} DESTINATION lib)
install(FILES ${HEADER_FILES} DESTINATION include/${CMAKE_PROJECT_NAME})
