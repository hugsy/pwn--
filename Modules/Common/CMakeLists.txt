project(Common CXX)
message(STATUS "Configuring module '${PROJECT_NAME}'")

set(PROJECT_DIR ${PWNLIB_MODULE_DIR}/${PROJECT_NAME})
set(INTERFACE_DIR ${PROJECT_DIR}/Include)
set(SOURCE_DIR ${PROJECT_DIR}/Source)
set(HEADER_DIR ${SOURCE_DIR}/Include)

set(SOURCE_FILES

    ${SOURCE_DIR}/Architecture.cpp
    ${SOURCE_DIR}/Context.cpp
    ${SOURCE_DIR}/Error.cpp
    ${SOURCE_DIR}/Log.cpp
    ${SOURCE_DIR}/Utils.cpp
)

#
# Create and build the target static library
#
add_library(${PROJECT_NAME} STATIC)
add_library(PWN::Common ALIAS ${PROJECT_NAME})
target_sources(${PROJECT_NAME} PRIVATE ${SOURCE_FILES})
target_compile_features(${PROJECT_NAME} PUBLIC cxx_std_20)
target_include_directories(${PROJECT_NAME} PUBLIC ${INTERFACE_DIR} PRIVATE ${HEADER_DIR})

if(PWN_LOG_USE_COLOR)
    target_compile_definitions(${PROJECT_NAME} PRIVATE PWN_LOG_USE_COLOR=1)
endif(PWN_LOG_USE_COLOR)

# target_precompile_headers(${PROJECT_NAME} INTERFACE ${INTERFACE_DIR}/pch.hpp)
if(WIN32)
    target_compile_definitions(${PROJECT_NAME} PUBLIC PWN_BUILD_FOR_WINDOWS)
    target_include_directories(${PROJECT_NAME} PUBLIC $<TARGET_PROPERTY:PWN::Deps::PHNT,INTERFACE_INCLUDE_DIRECTORIES>)

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

        $<$<COMPILE_LANGUAGE:CXX>:
        /Zc:__cplusplus
        /EHsc
        $<IF:$<CONFIG:Debug>,
        /sdl /WX /Gy /Gm- /permissive-,
        /WX /Zi /Zf /Gm /Gm- /permissive-
        >
        /diagnostics:caret /ZH:SHA_256

        # ASAN only supported for Intel
        $<$<STREQUAL:${CMAKE_GENERATOR_PLATFORM},x64>:$<$<CONFIG:Debug>:/fsanitize=address>>
        $<$<STREQUAL:${CMAKE_GENERATOR_PLATFORM},win32>:$<$<CONFIG:Debug>:/fsanitize=address>>
        >
        PRIVATE
    )

    #
    # Linker flags
    #
    target_link_options(${PROJECT_NAME}
        PUBLIC

        # Link ASAN for debug
        $<$<STREQUAL:${CMAKE_GENERATOR_PLATFORM},win32>:$<$<CONFIG:Debug>:/InferAsanLibs>>
        $<$<STREQUAL:${CMAKE_GENERATOR_PLATFORM},x64>:$<$<CONFIG:Debug>:/InferAsanLibs>>

        # Fix issues with SAFESEH linking for 32b
        $<$<STREQUAL:${CMAKE_GENERATOR_PLATFORM},win32>:/SAFESEH:NO>
        $<$<STREQUAL:${CMAKE_GENERATOR_PLATFORM},arm>:/SAFESEH:NO>
    )

    target_link_libraries(${PROJECT_NAME}
        PUBLIC
        ntdll.lib
    )

else()
    target_compile_definitions(${PROJECT_NAME} PUBLIC PWN_BUILD_FOR_LINUX)

    target_compile_options(${PROJECT_NAME}
        PUBLIC
        $<$<COMPILE_LANGUAGE:CXX>:
        $<$<CONFIG:Debug>:-fsanitize=address>
        >
        PRIVATE
    )
endif(WIN32)

install(DIRECTORY ${INTERFACE_DIR} DESTINATION ${CMAKE_PROJECT_NAME})

if(PWN_BUILD_TESTING)
    include(CTest)
    add_subdirectory(Tests)
endif(PWN_BUILD_TESTING)
