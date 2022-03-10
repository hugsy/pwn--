#
# Build Windows test tools
#

# todo:
# - harden with: add_compile_options(/W3 /WX /Wall /Wall /sdl /guard:cf /guard:ehcont /CETCOMPAT)

set(PWNLIB_TOOLS_WIN32_DIR ${PWNLIB_TOOLS_DIR}/win32 CACHE INTERNAL "PWNLIB_TOOLS_WIN32_DIR")


set(
    WIN32_TOOLS

    AppContainMe
    HexdumpFile
    ProcessReparent
    ExploitTemplate
)


foreach(TOOL_DIR ${WIN32_TOOLS})
    add_executable(${TOOL_DIR} ${PWNLIB_TOOLS_WIN32_DIR}/${TOOL_DIR}/main.cpp)
    add_dependencies(${TOOL_DIR} ${CMAKE_PROJECT_NAME})

    if(NOT INCLUDE_DISASSEMBLER)
        add_compile_definitions(PWN_NO_DISASSEMBLER)
    endif()

    if(NOT INCLUDE_ASSEMBLER)
        add_compile_definitions(PWN_NO_ASSEMBLER)
    endif()

    add_compile_definitions(_UNICODE UNICODE)

    target_include_directories(${TOOL_DIR} PUBLIC $<TARGET_PROPERTY:${CMAKE_PROJECT_NAME},INCLUDE_DIRECTORIES>)
    target_link_libraries(${TOOL_DIR} PRIVATE $<TARGET_LINKER_FILE:${CMAKE_PROJECT_NAME}>)

    install(TARGETS ${TOOL_DIR} DESTINATION tools)

    unset(SOURCE_FILES)
endforeach()
