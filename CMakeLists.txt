cmake_minimum_required(VERSION 3.26)
set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED True)
set(CMAKE_CXX_EXTENSIONS OFF)
set(VCPKG_MANIFEST_MODE OFF)

list(APPEND CMAKE_MODULE_PATH ${CMAKE_CURRENT_LIST_DIR}/cmake)
project(
    pwn++
    DESCRIPTION "A (toy) Windows & Linux pwn library to play with modern C++."
    HOMEPAGE_URL https://github.com/hugsy/pwn--
    VERSION 0.1.4
)

set(PROJECT_AUTHOR hugsy)
set(PROJECT_LICENSE MIT)

set(CXX_STANDARD 23)

set_property(GLOBAL PROPERTY USE_FOLDERS ON)

option(PWN_LOG_USE_COLOR "Use ANSI color codes in log messages" OFF)
option(PWN_DISASSEMBLE_X86 "Compile with Zydis disassembler support (X86/64 only)" ON)
option(PWN_DISASSEMBLE_ARM64 "Compile with BinaryNinja disassembler support (ARM64)" ON)

# Use CMake's `BUILD_SHARED_LIBS`
# option(PWN_BUILD_SHARED_LIBS "Build as a shared library" OFF)

if(CMAKE_CURRENT_SOURCE_DIR STREQUAL CMAKE_SOURCE_DIR)
    # pwn++ is NOT a top dir (i.e. build as dependency)
    option(PWN_BUILD_TOOLKIT "Compile the executables of pwn++ toolkit" OFF)
    option(PWN_BUILD_TESTING "Compile the test suite" OFF)
    option(PWN_BUILD_MODULE_CRYPTO "Compile the crypto module (requires m4)" OFF)
    option(PWN_BUILD_DOCS "Generate the Doxygen API files" OFF)
else()
    # pwn++ is a top dir
    option(PWN_BUILD_TOOLKIT "Compile the executables of pwn++ toolkit" ON)
    option(PWN_BUILD_TESTING "Compile the test suite" ON)
    option(PWN_BUILD_DOCS "Generate the Doxygen API files" OFF)
endif()

set(PWNLIB_ROOT_DIR ${CMAKE_CURRENT_LIST_DIR})

set(PWN_INCLUDE_DISASSEMBLER FALSE)
set(CMAKE_INSTALL_LIBDIR Library)
set(CMAKE_INSTALL_BINDIR Binary)
set(CMAKE_INSTALL_INCLUDEDIR Include)

if(WIN32)
    list(APPEND PWN_MODULES

        # Listed by dependency order
        Common

        # Crypto
        # Network
        # Symbols
        # System
        # Security
        # Registry
        # Service
        # Shellcode

        # FileSystem
        # Process
        # Remote

        # Binary
        # CTF

        # TODO : ideas for future modules
        # - WTS
    )

else()
    list(APPEND PWN_MODULES

        # Listed by dependency order
        Common

        Crypto
        Network
        System

        # Binary # TODO: ELF
        CTF
    )
endif(WIN32)

message(STATUS "Using ${CMAKE_CXX_COMPILER_ID} compiler.")

if(CMAKE_CXX_COMPILER_ID MATCHES "Clang" OR CMAKE_C_COMPILER_ID MATCHES "Clang")
    #
    # `std::format` was tested to work only in clang16 + libc++
    #
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -stdlib=libc++")
else()
    set(CMAKE_INTERPROCEDURAL_OPTIMIZATION True)
endif()

if(PWN_BUILD_MODULE_CRYPTO)
    find_package(MkCLib REQUIRED)
endif(PWN_BUILD_MODULE_CRYPTO)

if(PWN_DISASSEMBLE_X86)
    find_package(Zydis REQUIRED)
    set(PWN_INCLUDE_DISASSEMBLER TRUE)
endif()

if(PWN_DISASSEMBLE_ARM64)
    find_package(BinjaArm64 REQUIRED)
    set(PWN_INCLUDE_DISASSEMBLER TRUE)
endif()

if(WIN32)
    find_package(PhNt REQUIRED)
    install(DIRECTORY $<TARGET_PROPERTY:Deps_PhNt,INTERFACE_DIRECTORIES> DESTINATION ${PROJECT_NAME}/Dependencies/Include)
endif(WIN32)

if(PWN_INCLUDE_DISASSEMBLER)
    list(APPEND PWN_MODULES Assembly)
endif(PWN_INCLUDE_DISASSEMBLER)

if(MSVC)
    if("${CMAKE_GENERATOR_PLATFORM}" STREQUAL "x64")
        enable_language(CXX ASM_MASM)
    elseif("${CMAKE_GENERATOR_PLATFORM}" STREQUAL "win32")
        enable_language(CXX ASM_MASM)
    elseif("${CMAKE_GENERATOR_PLATFORM}" STREQUAL "arm")
        enable_language(CXX ASM_MARMASM)
    elseif("${CMAKE_GENERATOR_PLATFORM}" STREQUAL "arm64")
        enable_language(CXX ASM_MARMASM)
    endif()
else()
    enable_language(CXX ASM_NASM)
endif()

if(PWN_BUILD_TESTING)
    include(CTest)
    find_package(Catch2 REQUIRED)
endif()

if(PWN_BUILD_TOOLKIT)
    find_package(Argparse REQUIRED)

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

add_subdirectory(Modules)

add_subdirectory(pwn++)
