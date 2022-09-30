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
)

foreach(TOOL_DIR ${WIN32_TOOLS})
    add_executable(${TOOL_DIR} WIN32 ${PWNLIB_TOOLS_WIN32_DIR}/${TOOL_DIR}/main.cpp)
    add_dependencies(${TOOL_DIR} ${CMAKE_PROJECT_NAME})
    target_compile_features(${TOOL_DIR} PUBLIC cxx_std_20)
    set_target_properties(${TOOL_DIR} PROPERTIES CXX_STANDARD 20)

    target_compile_options(${TOOL_DIR} PRIVATE $<TARGET_PROPERTY:${CMAKE_PROJECT_NAME},INTERFACE_COMPILE_OPTIONS>)
    target_compile_definitions(${TOOL_DIR} PRIVATE $<TARGET_PROPERTY:${CMAKE_PROJECT_NAME},INTERFACE_COMPILE_DEFINITIONS>)
    target_include_directories(${TOOL_DIR} PRIVATE $<TARGET_PROPERTY:${CMAKE_PROJECT_NAME},INTERFACE_INCLUDE_DIRECTORIES>)
    target_link_libraries(${TOOL_DIR} PRIVATE ${CMAKE_PROJECT_NAME} $<TARGET_PROPERTY:${CMAKE_PROJECT_NAME},INTERFACE_LINK_LIBRARIES>)
    target_link_options(${TOOL_DIR} PRIVATE $<TARGET_PROPERTY:${CMAKE_PROJECT_NAME},INTERFACE_LINK_OPTIONS> /SUBSYSTEM:Console)

    install(TARGETS ${TOOL_DIR} DESTINATION tools)
endforeach()
