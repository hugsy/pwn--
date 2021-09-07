#
# Linux specific definitions
#
set(HEADER_DIR ${COMMON_HEADER_DIR}/linux)
set(
    HEADER_FILES
    ${COMMON_HEADER_FILES}
    ${HEADER_DIR}/system.hpp
    ${SOURCE_DIR}/ctf/remote.hpp
)

set(SOURCE_DIR ${COMMON_SOURCE_DIR}/linux)
set(
    SOURCE_FILES
    ${COMMON_SOURCE_FILES}
    ${SOURCE_DIR}/system.cpp
    ${SOURCE_DIR}/ctf/remote.cpp
)

add_library(pwn++ SHARED ${SOURCE_FILES})

# target_compile_options(pwn++ PRIVATE -Wno-ignored-optimization-argument -std=c++17)
target_compile_features(pwn++ PRIVATE cxx_std_17)
set_property(TARGET pwn++ PROPERTY CXX_STANDARD 17)
# add_compile_options(-W -Wall -Werror)
add_compile_options(-O2 -Werror -Walloca -Wcast-qual -Wconversion -Wformat=2 -Wformat-security -Wnull-dereference -Wstack-protector -Wstrict-overflow=3 -Wvla -Warray-bounds -Warray-bounds-pointer-arithmetic -Wassign-enum -Wbad-function-cast -Wconditional-uninitialized -Wconversion -Wfloat-equal -Wformat-type-confusion -Widiomatic-parentheses -Wimplicit-fallthrough -Wloop-analysis -Wpointer-arith -Wshift-sign-overflow -Wshorten-64-to-32 -Wswitch-enum -Wtautological-constant-in-range-compare -Wunreachable-code-aggressive  -D_FORTIFY_SOURCE=2 -fstack-protector-strong -fsanitize=safe-stack -fPIE -fstack-clash-protection -Wl,-z,relro -Wl,-z,now -Wl,-z,noexecstack -Wl,-z,separate-code)

if(DEBUG)
    add_compile_definitions(DEBUG)
endif()

if(NOT INCLUDE_DISASSEMBLER)
    add_compile_definitions(PWN_NO_DISASSEMBLER)
endif()

if(NOT INCLUDE_ASSEMBLER)
    add_compile_definitions(PWN_NO_ASSEMBLER)
endif()

target_include_directories(pwn++ PUBLIC ${COMMON_HEADER_DIR} ${HEADER_DIR})
target_include_directories(pwn++ PRIVATE ${COMMON_SOURCE_DIR} ${SOURCE_DIR})

target_link_libraries(
    pwn++
    PRIVATE
    pthread
    dl
)