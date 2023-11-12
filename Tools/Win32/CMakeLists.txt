#
# Build Windows test tools
#

set(PWNLIB_TOOLS_WIN32_DIR ${PWNLIB_ROOT_DIR}/Tools/Win32 CACHE INTERNAL "PWNLIB_TOOLS_WIN32_DIR")

set(
    WIN32_TOOLS

    AppContainMe
    BasicExample
    ExploitTemplate
    HexdumpFile
    LoadDriver
    ProcessReparent
    ProcessGhosting
)

foreach(TOOL_DIR ${WIN32_TOOLS})
    file(GLOB SOURCE_FILES ${PWNLIB_TOOLS_WIN32_DIR}/${TOOL_DIR}/*.cpp ${PWNLIB_TOOLS_WIN32_DIR}/${TOOL_DIR}/*.asm)
    add_executable(${TOOL_DIR} WIN32 ${SOURCE_FILES})
    add_dependencies(${TOOL_DIR} ${CMAKE_PROJECT_NAME})
    target_compile_features(${TOOL_DIR} PUBLIC cxx_std_20)
    set_target_properties(${TOOL_DIR} PROPERTIES CXX_STANDARD 20)

    target_compile_definitions(${TOOL_DIR} PUBLIC PWN_BUILD_FOR_WINDOWS)
    target_compile_options(${TOOL_DIR}
        PUBLIC
        $<$<STREQUAL:${CMAKE_GENERATOR_PLATFORM},x64>:$<$<CONFIG:Debug>:/fsanitize=address>>
        $<$<STREQUAL:${CMAKE_GENERATOR_PLATFORM},win32>:$<$<CONFIG:Debug>:/fsanitize=address>>
    )

    target_link_options(${TOOL_DIR}
        PUBLIC
        $<$<STREQUAL:${CMAKE_GENERATOR_PLATFORM},x64>:$<$<CONFIG:Debug>:/InferAsanLibs>>
        $<$<STREQUAL:${CMAKE_GENERATOR_PLATFORM},win32>:$<$<CONFIG:Debug>:/InferAsanLibs>>
    )
    target_compile_options(${TOOL_DIR} PRIVATE $<TARGET_PROPERTY:${CMAKE_PROJECT_NAME},INTERFACE_COMPILE_OPTIONS>)
    target_compile_definitions(${TOOL_DIR} PRIVATE $<TARGET_PROPERTY:${CMAKE_PROJECT_NAME},INTERFACE_COMPILE_DEFINITIONS>)
    target_include_directories(${TOOL_DIR}
        PRIVATE
        $<TARGET_PROPERTY:${CMAKE_PROJECT_NAME},INTERFACE_INCLUDE_DIRECTORIES>
        $<TARGET_PROPERTY:Deps_ArgParse,INTERFACE_INCLUDE_DIRECTORIES>
    )
    target_link_libraries(${TOOL_DIR} PRIVATE ${CMAKE_PROJECT_NAME} $<TARGET_PROPERTY:${CMAKE_PROJECT_NAME},INTERFACE_LINK_LIBRARIES>)
    target_link_options(${TOOL_DIR} PRIVATE $<TARGET_PROPERTY:${CMAKE_PROJECT_NAME},INTERFACE_LINK_OPTIONS> /SUBSYSTEM:Console)

    install(TARGETS ${TOOL_DIR} DESTINATION Tools)
    install(FILES $<TARGET_PDB_FILE:${TOOL_DIR}> DESTINATION Tools/Debug OPTIONAL)
endforeach()
