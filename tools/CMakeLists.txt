#
# Build pwn++.{dll,so}
#
project(pwn++-shared)

set(PWNLIB_TOOLS_DIR ${PWNLIB_ROOT_DIR}/tools CACHE INTERNAL "PWNLIB_TOOLS_DIR")

add_library(${PROJECT_NAME} SHARED)
add_dependencies(${PROJECT_NAME} ${CMAKE_PROJECT_NAME})

target_compile_features(${PROJECT_NAME} PUBLIC cxx_std_20)
set_target_properties(${PROJECT_NAME} PROPERTIES CXX_STANDARD 20)

target_compile_options(${PROJECT_NAME} PRIVATE $<TARGET_PROPERTY:${CMAKE_PROJECT_NAME},INTERFACE_COMPILE_OPTIONS>)
target_compile_definitions(${PROJECT_NAME} PRIVATE $<TARGET_PROPERTY:${CMAKE_PROJECT_NAME},INTERFACE_COMPILE_DEFINITIONS>)
target_include_directories(${PROJECT_NAME} PRIVATE $<TARGET_PROPERTY:${CMAKE_PROJECT_NAME},INTERFACE_INCLUDE_DIRECTORIES>)
target_link_libraries(${PROJECT_NAME} PRIVATE ${CMAKE_PROJECT_NAME} $<TARGET_PROPERTY:${CMAKE_PROJECT_NAME},INTERFACE_LINK_LIBRARIES>)

if(WIN32)
    target_sources(${PROJECT_NAME} PRIVATE win32/dllmain.cpp)

    target_link_options(
        ${PROJECT_NAME}

        PRIVATE
        $<TARGET_PROPERTY:${CMAKE_PROJECT_NAME},INTERFACE_LINK_OPTIONS>
        /DEBUG:FULL /WX /RELEASE /SUBSYSTEM:Console /MANIFEST:NO /DLL
        /profile /guard:cf /DEBUGTYPE:cv,fixup /LARGEADDRESSAWARE
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
