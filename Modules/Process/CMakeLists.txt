project(Process CXX)
message(STATUS "Configuring module '${PROJECT_NAME}'")

set(PROJECT_DIR ${PWNLIB_MODULE_DIR}/${PROJECT_NAME})
set(INTERFACE_DIR ${PROJECT_DIR}/Include)
set(SOURCE_DIR ${PROJECT_DIR}/Source)
set(HEADER_DIR ${SOURCE_DIR}/Include)
set(TEST_DIR ${PROJECT_DIR}/Tests)

if("${CMAKE_GENERATOR_PLATFORM}" STREQUAL x64)
    set(ASM_DIR ${SOURCE_DIR}/Win32/asm/x64)
elseif("${CMAKE_GENERATOR_PLATFORM}" STREQUAL win32)
    set(ASM_DIR ${SOURCE_DIR}/Win32/asm/x86)
elseif("${CMAKE_GENERATOR_PLATFORM}" STREQUAL arm64)
    set(ASM_DIR ${SOURCE_DIR}/Win32/asm/arm64)
elseif("${CMAKE_GENERATOR_PLATFORM}" STREQUAL arm)
    set(ASM_DIR ${SOURCE_DIR}/Win32/asm/arm)
else()
    message(FATAL_ERROR "Unknown arch ${CMAKE_GENERATOR_PLATFORM}")
endif()

if(WIN32)
    set(SOURCE_FILES
        ${SOURCE_DIR}/Win32/Process.cpp
        ${SOURCE_DIR}/Win32/Thread.cpp
        ${SOURCE_DIR}/Win32/Job.cpp
        ${SOURCE_DIR}/Win32/Memory.cpp
        ${SOURCE_DIR}/Win32/ThreadGroup.cpp
        ${SOURCE_DIR}/Win32/Detour.cpp

        ${ASM_DIR}/get_teb.asm
        ${ASM_DIR}/trampoline.asm
    )
    set(DEPS PWN::Common PWN::Security PWN::Symbols PWN::System)
else()
    return()
endif(WIN32)

add_library(${PROJECT_NAME} STATIC ${SOURCE_FILES})
add_dependencies(${PROJECT_NAME} ${DEPS})
add_library(PWN::${PROJECT_NAME} ALIAS ${PROJECT_NAME})
target_include_directories(${PROJECT_NAME} PUBLIC ${INTERFACE_DIR} PRIVATE ${HEADER_DIR})

# target_compile_definitions(${PROJECT_NAME} PUBLIC)
target_link_libraries(${PROJECT_NAME} PUBLIC ${DEPS} Userenv.lib Ole32.lib)

install(DIRECTORY ${INTERFACE_DIR} DESTINATION ${CMAKE_PROJECT_NAME})

if(PWN_BUILD_TESTING)
    include(CTest)
    add_subdirectory(Tests)
endif(PWN_BUILD_TESTING)
