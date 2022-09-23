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
    ${HEADER_DIR}/cpu.hpp
    ${HEADER_DIR}/registry.hpp
    ${HEADER_DIR}/kernel.hpp
    ${HEADER_DIR}/job.hpp
    ${HEADER_DIR}/service.hpp
    ${HEADER_DIR}/fs.hpp
    ${HEADER_DIR}/alpc.hpp
    ${HEADER_DIR}/rpc.hpp
    ${HEADER_DIR}/ctf/remote.hpp
)

set(
    SOURCE_FILES

    ${SOURCE_DIR}/system.cpp
    ${SOURCE_DIR}/process.cpp
    ${SOURCE_DIR}/thread.cpp
    ${SOURCE_DIR}/cpu.cpp
    ${SOURCE_DIR}/kernel.cpp
    ${SOURCE_DIR}/job.cpp
    ${SOURCE_DIR}/service.cpp
    ${SOURCE_DIR}/fs.cpp
    ${SOURCE_DIR}/alpc.cpp
    ${SOURCE_DIR}/rpc.cpp
    ${SOURCE_DIR}/ctf/remote.cpp

    ${SOURCE_DIR}/get_teb64.asm
)

if(PWN_ENABLE_LUA_BACKDOOR)
    set(SOURCE_FILES ${SOURCE_FILES} ${SOURCE_DIR}/backdoor.cpp)
endif(PWN_ENABLE_LUA_BACKDOOR)

target_sources(
    ${PROJECT_NAME}
    PUBLIC ${HEADER_FILES}
    PRIVATE ${SOURCE_FILES}
)

target_include_directories(
    ${PROJECT_NAME}
    PUBLIC ${HEADER_DIR}
)


#
# Compiler flags
#

target_compile_definitions(${PROJECT_NAME} PRIVATE _UNICODE UNICODE)

target_compile_options(
    ${PROJECT_NAME}
    PUBLIC
        $<$<COMPILE_LANGUAGE:CXX>:/Zc:__cplusplus>
    PRIVATE
        /diagnostics:caret /Zl /ZH:SHA_256
)

if(DEBUG)
    target_compile_options(
        ${PROJECT_NAME}
        PUBLIC
            /sdl /WX /Gy /Gm- /permissive-
        )
    target_link_options(${PROJECT_NAME}
        PUBLIC
            /DEBUG:FULL
        PRIVATE
            /profile /DEBUGTYPE:cv,fixup
    )
else()
    target_compile_options(
        ${PROJECT_NAME}
        PUBLIC
            /RELEASE /WX /Zi /Zf /Gm /Gm- /permissive-
            /guard:cf /guard:ehcont
        )
    target_link_options(
        ${PROJECT_NAME}
        PUBLIC
    )
endif(DEBUG)


#
# Linker flags
#

target_link_options(
    ${PROJECT_NAME}
    PUBLIC
        /CETCOMPAT
    PRIVATE
        /LARGEADDRESSAWARE /Zp8
)

target_link_libraries(
    ${PROJECT_NAME}
    PUBLIC
        ws2_32.lib
        Userenv.lib
        Rpcrt4.lib
)
