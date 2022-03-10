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

add_library(${CMAKE_PROJECT_NAME} SHARED ${SOURCE_FILES})

target_compile_features(${CMAKE_PROJECT_NAME} PRIVATE cxx_std_20)
set_property(TARGET ${CMAKE_PROJECT_NAME} PROPERTY CXX_STANDARD 20)

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

target_precompile_headers(${CMAKE_PROJECT_NAME} PRIVATE ${PWNLIB_SRC_HDR_DIR}/pch.hpp)
target_include_directories(${CMAKE_PROJECT_NAME} PUBLIC ${COMMON_HEADER_DIR} ${HEADER_DIR})
target_include_directories(${CMAKE_PROJECT_NAME} PRIVATE ${COMMON_SOURCE_DIR} ${SOURCE_DIR})

set_target_properties(
    ${CMAKE_PROJECT_NAME}
    PROPERTIES
    VERSION ${PROJECT_VERSION}
    SOVERSION ${PROJECT_VERSION_MAJOR}
)

target_link_libraries(
    ${CMAKE_PROJECT_NAME}
    PRIVATE
    pthread
    dl
)


#
# Installation directives
#
install(TARGETS ${CMAKE_PROJECT_NAME} DESTINATION lib)
install(FILES ${HEADER_FILES} DESTINATION include/${CMAKE_PROJECT_NAME})
