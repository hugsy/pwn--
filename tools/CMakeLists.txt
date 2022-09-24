#
# Build pwn++.{dll,so}
#
project(pwn++-shared)

set(PWNLIB_TOOLS_DIR ${PWNLIB_ROOT_DIR}/tools CACHE INTERNAL "PWNLIB_TOOLS_DIR")

add_library(${PROJECT_NAME} SHARED)
add_dependencies(${PROJECT_NAME} ${CMAKE_PROJECT_NAME})

target_compile_definitions(
    ${PROJECT_NAME}
    PRIVATE
    $<$<CONFIG:Debug>:_DEBUG DEBUG>
)

if(WIN32)
    target_sources(${PROJECT_NAME} PRIVATE win32/dllmain.cpp)

    target_compile_definitions(${PROJECT_NAME} PRIVATE _UNICODE UNICODE)

    target_include_directories(
        ${PROJECT_NAME}

        PUBLIC
        $<TARGET_PROPERTY:${CMAKE_PROJECT_NAME},INCLUDE_DIRECTORIES>
    )

    target_link_options(
        ${PROJECT_NAME}

        PRIVATE
        /DEBUG:FULL /WX /RELEASE /SUBSYSTEM:Console /MANIFEST:NO /DLL
        /profile /guard:cf /DEBUGTYPE:cv,fixup /LARGEADDRESSAWARE
    )

    target_link_libraries(
        ${PROJECT_NAME}

        PUBLIC
        $<TARGET_LINKER_FILE:${CMAKE_PROJECT_NAME}>

        PRIVATE
        Userenv
    )

else()
    target_sources(${PROJECT_NAME} PRIVATE linux/dllmain.cpp)

    target_link_libraries(
        ${PROJECT_NAME}

        PRIVATE
        $<TARGET_LINKER_FILE:${CMAKE_PROJECT_NAME}>
        pthread
        dl
    )
endif(WIN32)

if(PWN_ENABLE_LUA_BACKDOOR)
    target_link_libraries(${PROJECT_NAME} PRIVATE lua::lib)
    target_include_directories(${PROJECT_NAME} PRIVATE ${PWNLIB_ROOT_DIR}/deps/lua/include)
endif()

#
# Installation directives
#
install(TARGETS ${PROJECT_NAME} DESTINATION lib)
install(FILES $<TARGET_PROPERTY:pwn++,HEADER_FILES> DESTINATION include/${CMAKE_PROJECT_NAME})

#
# Build the tools in the subdirectories
#
if(WIN32)
    add_subdirectory(win32)
else()
    add_subdirectory(linux)
endif(WIN32)
