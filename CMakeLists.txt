cmake_minimum_required(VERSION 3.26)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED True)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_INTERPROCEDURAL_OPTIMIZATION True)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_LIST_DIR}/cmake")

project(
    pwn++
    DESCRIPTION "A (toy) Windows & Linux pwn library to play with modern C++."
    HOMEPAGE_URL https://github.com/hugsy/pwn--
    VERSION 0.1.3
)

set(PROJECT_AUTHOR hugsy)
set(PROJECT_LICENSE MIT)

set(CXX_STANDARD 20)

set_property(GLOBAL PROPERTY USE_FOLDERS ON)

option(PWN_LOG_USE_COLOR "Use ANSI color codes in log messages" OFF)
option(PWN_DISASSEMBLE_X86 "Compile with Zydis disassembler support (X86/64 only)" ON)
option(PWN_DISASSEMBLE_ARM64 "Compile with BinaryNinja disassembler support (ARM64)" ON)
option(PWN_BUILD_TOOLKIT "Compile the executables of pwn++ toolkit" ON)
option(PWN_BUILD_TESTING "Compile the test suite" ON)
option(PWN_BUILD_DOCS "Generate the Doxygen API files" OFF)
option(PWN_ENABLE_LUA_BACKDOOR "Enable Lua scripting for backdoor" OFF)

set(PWNLIB_ROOT_DIR ${CMAKE_CURRENT_LIST_DIR})
set(PWNLIB_DEPS_DIR ${PWNLIB_ROOT_DIR}/Deps)

set(PWN_INCLUDE_DISASSEMBLER FALSE)
set(CMAKE_INSTALL_LIBDIR Library)
set(CMAKE_INSTALL_BINDIR Binary)
set(CMAKE_INSTALL_INCLUDEDIR Include)

list(APPEND PWN_MODULES

    # Listed by dependency order
    Common

    Crypto
    Network
    Symbols
    System
    Security
    Registry
    Service
    Shellcode

    FileSystem
    Process
    Remote

    Binary

    # CTF

    #

    # TODO : ideas for future modules
    # - Win32/WTS
)

if(PWN_DISASSEMBLE_X86)
    option(ZYCORE_BUILD_SHARED_LIB "" OFF)
    option(ZYDIS_BUILD_TOOLS "" OFF)
    option(ZYDIS_BUILD_EXAMPLES "" OFF)
    option(ZYDIS_BUILD_SHARED_LIB "" OFF)
    option(ZYDIS_FEATURE_ENCODER "" OFF)
    option(ZYDIS_BUILD_DOXYGEN "" OFF)
    option(ZYDIS_BUILD_EXAMPLES "" OFF)
    cmake_policy(PUSH)
    set(CMAKE_POLICY_DEFAULT_CMP0069 NEW)
    add_subdirectory(${PWNLIB_DEPS_DIR}/Zydis)
    cmake_policy(POP)
    set(PWN_INCLUDE_DISASSEMBLER TRUE)
    add_library(PWN::Deps::Zydis ALIAS Zydis)

    install(TARGETS Zydis DESTINATION ${PROJECT_NAME}/Dependencies/Library)
    install(DIRECTORY $<TARGET_PROPERTY:Zydis,INTERFACE_DIRECTORIES> DESTINATION ${PROJECT_NAME}/Dependencies/Include)
endif()

if(PWN_DISASSEMBLE_ARM64)
    option(BUILD_SHARED_LIBS "" OFF)
    add_subdirectory(${PWNLIB_DEPS_DIR}/arch-arm64)
    set(PWN_INCLUDE_DISASSEMBLER TRUE)
    add_library(PWN::Deps::BinjaArm64 ALIAS disass_arch_arm64)

    install(TARGETS disass_arch_arm64 DESTINATION ${PROJECT_NAME}/Dependencies/Library)
    install(DIRECTORY $<TARGET_PROPERTY:disass_arch_arm64,INTERFACE_DIRECTORIES> DESTINATION ${PROJECT_NAME}/Dependencies/Include)

    # TODO replace with mainstream
endif()

if(WIN32)
    add_subdirectory(${PWNLIB_DEPS_DIR}/phnt)
    add_library(PWN::Deps::PHNT ALIAS phnt)
    install(DIRECTORY $<TARGET_PROPERTY:phnt,INTERFACE_DIRECTORIES> DESTINATION ${PROJECT_NAME}/Dependencies/Include)
endif(WIN32)

if(PWN_ENABLE_LUA_BACKDOOR)
    option(BUILD_SHARED_LIBS "" OFF)
    add_subdirectory(${PWNLIB_DEPS_DIR}/lua)
    add_library(PWN::Deps::Lua ALIAS lua)

    install(TARGETS lua DESTINATION ${PROJECT_NAME}/Dependencies/Library)
    install(TARGETS lua-header DESTINATION ${PROJECT_NAME}/Dependencies/Include)

    list(APPEND PWN_MODULES Backdoor)
endif()

if(PWN_INCLUDE_DISASSEMBLER)
    list(APPEND PWN_MODULES Assembly)
endif(PWN_INCLUDE_DISASSEMBLER)

if("${CMAKE_GENERATOR_PLATFORM}" STREQUAL "arm64")
    enable_language(CXX ASM_MARMASM)
elseif("${CMAKE_GENERATOR_PLATFORM}" STREQUAL "x64")
    enable_language(CXX ASM_MASM)
elseif("${CMAKE_GENERATOR_PLATFORM}" STREQUAL "win32")
    enable_language(CXX ASM_MASM)
else()
    if(NOT ${PWN_BUILD_DOCS})
        #
        # Unless we're generating docs, we need to make sure there's an assembler available
        #
        message(FATAL_ERROR "No ASSEMBLY mode available")
    endif(NOT ${PWN_BUILD_DOCS})
endif()

add_subdirectory(Modules)

add_subdirectory(pwn++)

if(PWN_BUILD_TESTING)
    include(CTest)

    add_library(Deps_Catch2 INTERFACE)
    target_include_directories(Deps_Catch2 INTERFACE ${PWNLIB_DEPS_DIR}/Catch2)

    if(WIN32)
        target_compile_definitions(Deps_Catch2 INTERFACE CATCH_CONFIG_NO_WINDOWS_SEH)
    else()
        target_compile_definitions(Deps_Catch2 INTERFACE _GNU_SOURCE=1)
    endif(WIN32)

    add_library(PWN::Deps::Catch2 ALIAS Deps_Catch2)

    enable_testing()
endif()

if(PWN_BUILD_TOOLKIT)
    add_library(Deps_ArgParse INTERFACE EXCLUDE_FROM_ALL)
    add_library(PWN::Deps::ArgParse ALIAS Deps_ArgParse)
    target_compile_features(Deps_ArgParse INTERFACE cxx_std_17)
    target_include_directories(Deps_ArgParse INTERFACE $<BUILD_INTERFACE:${PWNLIB_DEPS_DIR}/argparse>)

    if(WIN32)
        add_subdirectory(Tools/Win32)
    else()
        add_subdirectory(Tools/Linux)
    endif(WIN32)
endif()

if(PWN_BUILD_DOCS)
    find_package(Doxygen REQUIRED)
    add_subdirectory(Docs)
endif()
