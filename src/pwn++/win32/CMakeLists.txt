#
# Windows specific definitions
#

enable_language(C ASM_MASM)

set(HEADER_DIR ${PWNLIB_SRC_HDR_DIR}/win32)
set(SOURCE_DIR ${PWNLIB_SRC_LIB_DIR}/win32)

#
# Source files
#
set(
    HEADER_FILES

    ${HEADER_DIR}/framework.hpp
    ${HEADER_DIR}/system.hpp
    ${HEADER_DIR}/process.hpp
    ${HEADER_DIR}/thread.hpp
    ${HEADER_DIR}/token.hpp
    ${HEADER_DIR}/registry.hpp
    ${HEADER_DIR}/kernel.hpp
    ${HEADER_DIR}/job.hpp
    ${HEADER_DIR}/service.hpp
    ${HEADER_DIR}/fs.hpp
    ${HEADER_DIR}/alpc.hpp
    ${HEADER_DIR}/rpc.hpp
    ${HEADER_DIR}/object.hpp
    ${HEADER_DIR}/ctf/remote.hpp
)

set(
    SOURCE_FILES

    ${SOURCE_DIR}/system.cpp
    ${SOURCE_DIR}/process.cpp
    ${SOURCE_DIR}/thread.cpp
    ${SOURCE_DIR}/token.cpp
    ${SOURCE_DIR}/kernel.cpp
    ${SOURCE_DIR}/job.cpp
    ${SOURCE_DIR}/service.cpp
    ${SOURCE_DIR}/fs.cpp
    ${SOURCE_DIR}/alpc.cpp
    ${SOURCE_DIR}/rpc.cpp
    ${SOURCE_DIR}/object.cpp
    ${SOURCE_DIR}/ctf/remote.cpp

    $<$<STREQUAL:$<LOWER_CASE:${CMAKE_GENERATOR_PLATFORM}>,"x64">:${SOURCE_DIR}/asm/get_teb.asm>
    $<$<STREQUAL:$<LOWER_CASE:${CMAKE_GENERATOR_PLATFORM}>,"x64">:${SOURCE_DIR}/asm/copy_system_token.asm>

    $<$<STREQUAL:$<LOWER_CASE:${CMAKE_GENERATOR_PLATFORM}>,"win32">:${SOURCE_DIR}/asm/get_teb.asm>
)

if(PWN_ENABLE_LUA_BACKDOOR)
    set(SOURCE_FILES ${SOURCE_FILES} ${SOURCE_DIR}/backdoor.cpp)
endif(PWN_ENABLE_LUA_BACKDOOR)

target_sources(${PROJECT_NAME} PUBLIC ${HEADER_FILES} PRIVATE ${SOURCE_FILES})
target_include_directories(${PROJECT_NAME} PUBLIC ${HEADER_DIR})

#
# Use ProcessHacker phnt headers
#
target_include_directories(${PROJECT_NAME} PUBLIC ${PWNLIB_ROOT_DIR}/deps/phnt)
target_compile_definitions(${PROJECT_NAME} PUBLIC PHNT_VERSION=PHNT_20H2)

#
# Compiler flags
#
target_compile_definitions(
    ${PROJECT_NAME}
    PUBLIC
    _UNICODE UNICODE
    $<$<CONFIG:Debug>:_DISABLE_VECTOR_ANNOTATION _DISABLE_STRING_ANNOTATION >

    PRIVATE
)

target_compile_options(
    ${PROJECT_NAME}
    PUBLIC
    $<$<COMPILE_LANGUAGE:CXX>:/Zc:__cplusplus>
    $<$<CONFIG:Debug>:/fsanitize=address>

    PRIVATE
    /diagnostics:caret /Zl /ZH:SHA_256
    $<IF:$<CONFIG:Debug>,/sdl /WX /Gy /Gm- /permissive-,/WX /Zi /Zf /Gm /Gm- /permissive- >
)

#
# Linker flags
#
target_link_options(
    ${PROJECT_NAME}
    PUBLIC
    /CETCOMPAT
    /LARGEADDRESSAWARE
    $<$<CONFIG:Debug>:/InferAsanLibs>

    PRIVATE
)

target_link_libraries(
    ${PROJECT_NAME}
    PUBLIC
    ntdll.lib
    ws2_32.lib
    Userenv.lib
    Rpcrt4.lib
    BCrypt.lib
)
