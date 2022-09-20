#
# Build Windows test tools
#

set(PWNLIB_TOOLS_WIN32_DIR ${PWNLIB_TOOLS_DIR}/win32 CACHE INTERNAL "PWNLIB_TOOLS_WIN32_DIR")

set(
    WIN32_TOOLS

    AppContainMe
    Backdoor
    BasicExample
    ExploitTemplate
    HexdumpFile
    ProcessReparent
    SyscallTrace
)

foreach(TOOL_DIR ${WIN32_TOOLS})
    add_executable(${TOOL_DIR} WIN32 ${PWNLIB_TOOLS_WIN32_DIR}/${TOOL_DIR}/main.cpp)
    add_dependencies(${TOOL_DIR} ${CMAKE_PROJECT_NAME})

    if(DEBUG)
        target_compile_definitions(${TOOL_DIR} PRIVATE _DEBUG DEBUG)
    endif(DEBUG)

    target_include_directories(${TOOL_DIR} PRIVATE ${PWNLIB_ROOT_DIR}/deps/phnt)

    target_compile_options(${TOOL_DIR} PRIVATE $<TARGET_PROPERTY:${CMAKE_PROJECT_NAME},INTERFACE_COMPILE_OPTIONS>)
    target_compile_definitions(${TOOL_DIR} PRIVATE _UNICODE UNICODE)
    target_include_directories(${TOOL_DIR} PRIVATE ${CMAKE_PROJECT_NAME})
    target_link_options(${TOOL_DIR} PRIVATE /SUBSYSTEM:Console /LARGEADDRESSAWARE)
    target_link_libraries(${TOOL_DIR} PRIVATE ${CMAKE_PROJECT_NAME})

    if(PWN_ENABLE_LUA_BACKDOOR)
        target_link_libraries(${TOOL_DIR} PRIVATE lua::lib)
        target_include_directories(${TOOL_DIR} PRIVATE ${PWNLIB_ROOT_DIR}/deps/lua/include)
    endif()

    install(TARGETS ${TOOL_DIR} DESTINATION tools)
endforeach()
