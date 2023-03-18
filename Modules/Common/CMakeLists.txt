project(Common CXX)
message(STATUS "Configuring module '${PROJECT_NAME}'")

set(PROJECT_DIR ${PWNLIB_MODULE_DIR}/${PROJECT_NAME})
set(INTERFACE_DIR ${PROJECT_DIR}/Include)
set(SOURCE_DIR ${PROJECT_DIR}/Source)
set(HEADER_DIR ${SOURCE_DIR}/Include)
list(APPEND SOURCE_FILES)

if(WIN32)
    list(APPEND SOURCE_FILES

        ${SOURCE_DIR}/Architecture.cpp
        ${SOURCE_DIR}/Context.cpp
        ${SOURCE_DIR}/Error.cpp
        ${SOURCE_DIR}/Log.cpp
        ${SOURCE_DIR}/Utils.cpp
    )
else()
endif()

#
# Create and build the target static library
#
add_library(${PROJECT_NAME} STATIC ${SOURCE_FILES})
add_library(PWN::Common ALIAS ${PROJECT_NAME})
target_compile_features(${PROJECT_NAME} PUBLIC cxx_std_20)
target_precompile_headers(${PROJECT_NAME} PUBLIC ${INTERFACE_DIR}/pch.hpp)
target_include_directories(${PROJECT_NAME} PUBLIC ${INTERFACE_DIR} PRIVATE ${HEADER_DIR})

if(MSVC)
    target_compile_definitions(${PROJECT_NAME} PUBLIC PWN_BUILD_FOR_WINDOWS)
    target_include_directories(${PROJECT_NAME} PUBLIC $<TARGET_PROPERTY:PWN::Deps::PHNT,INTERFACE_INCLUDE_DIRECTORIES>)
else()
    target_compile_definitions(${PROJECT_NAME} PUBLIC PWN_BUILD_FOR_LINUX)
endif(MSVC)

#
# Compiler flags
#
target_compile_definitions(${PROJECT_NAME}
    PUBLIC
    _UNICODE UNICODE
    $<$<CONFIG:Debug>:_DISABLE_VECTOR_ANNOTATION _DISABLE_STRING_ANNOTATION >
    PRIVATE
)

target_compile_options(${PROJECT_NAME}
    PUBLIC
    $<$<COMPILE_LANGUAGE:CXX>:/Zc:__cplusplus>
    $<IF:$<CONFIG:Debug>,/sdl /WX /Gy /Gm- /permissive-,/WX /Zi /Zf /Gm /Gm- /permissive- >
    $<$<NOT:$<STREQUAL:${CMAKE_GENERATOR_PLATFORM},arm64>>:$<$<CONFIG:Debug>:/fsanitize=address>>
    /diagnostics:caret /ZH:SHA_256

    PRIVATE
)

#
# Linker flags
#
target_link_options(${PROJECT_NAME}
    PUBLIC

    $<$<NOT:$<STREQUAL:${CMAKE_GENERATOR_PLATFORM},arm64>>:$<$<CONFIG:Debug>:/InferAsanLibs>>
    $<$<STREQUAL:${CMAKE_GENERATOR_PLATFORM},win32>:/SAFESEH:NO>
)

target_link_libraries(${PROJECT_NAME}
    PUBLIC
    ntdll.lib
)

install(DIRECTORY ${INTERFACE_DIR} DESTINATION ${CMAKE_PROJECT_NAME})

if(PWN_BUILD_TESTING)
    add_subdirectory(Tests)
endif(PWN_BUILD_TESTING)
