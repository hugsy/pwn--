#
# Linux specific definitions
#

set(SOURCE_DIR ${COMMON_SOURCE_DIR}/linux)
set(HEADER_DIR ${COMMON_HEADER_DIR}/linux)

#
# Source files
#
set(
    HEADER_FILES

    ${HEADER_DIR}/framework.hpp

    ${HEADER_DIR}/system.hpp
    ${HEADER_DIR}/ctf/remote.hpp
)

set(
    SOURCE_FILES

    ${SOURCE_DIR}/system.cpp
    ${SOURCE_DIR}/ctf/remote.cpp
)

target_sources(
    ${PROJECT_NAME}
    PUBLIC ${HEADER_FILES}
    PRIVATE ${SOURCE_FILES}
)

target_include_directories(
    ${PROJECT_NAME}

    PUBLIC
    ${HEADER_DIR}

    PRIVATE
    ${SOURCE_DIR}
)

#
# Compiler flags
#
target_compile_options(
    ${PROJECT_NAME}
    PRIVATE
    -O2 -Werror -Walloca -Wcast-qual -Wconversion -Wformat=2 -Wformat-security
    -Wnull-dereference -Wstack-protector -Wstrict-overflow=3 -Wvla -Warray-bounds
    -Warray-bounds-pointer-arithmetic -Wassign-enum -Wbad-function-cast -Wconditional-uninitialized
    -Wconversion -Wfloat-equal -Wformat-type-confusion -Widiomatic-parentheses -Wimplicit-fallthrough
    -Wloop-analysis -Wpointer-arith -Wshift-sign-overflow -Wshorten-64-to-32 -Wswitch-enum
    -Wtautological-constant-in-range-compare -Wunreachable-code-aggressive -D_FORTIFY_SOURCE=2
    -fstack-protector-strong -fPIE -fstack-clash-protection -fsanitize=safe-stack
)

set_target_properties(
    ${PROJECT_NAME}
    PROPERTIES
    VERSION ${PROJECT_VERSION}
    SOVERSION ${PROJECT_VERSION_MAJOR}
)

#
# Linker flags
#
target_link_options(
    ${PROJECT_NAME}
    PRIVATE
    -Wl,-z,relro
    -Wl,-z,now -Wl,-z,noexecstack -Wl,-z,separate-code
)

target_link_libraries(
    ${PROJECT_NAME}

    PRIVATE
    pthread
    dl
)

#
# Minor adjustments:
#
# On Linux, std::format is only supported on clang-15 with experimental-library, not at
# all on gcc
#
if(CMAKE_CXX_COMPILER MATCHES gcc)
    message(FATAL_ERROR "std::format requires clang-15+ and libc++-15+")
endif()

if(CMAKE_CXX_COMPILER_VERSION VERSION_GREATER_EQUAL 15)
    target_compile_options(
        ${PROJECT_NAME}
        PUBLIC
        -fexperimental-library -stdlib=libc++
    )
endif()

#
# Installation directives
#
install(FILES ${COMMON_HEADER_FILES} DESTINATION include/${PROJECT_NAME})
install(FILES ${HEADER_FILES} DESTINATION include/${PROJECT_NAME}/linux)
