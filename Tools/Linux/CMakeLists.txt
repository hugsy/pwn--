#
# Build Linux test tools
#

set(PWNLIB_TOOLS_LINUX_DIR ${PWNLIB_ROOT_DIR}/Tools/Linux CACHE INTERNAL "PWNLIB_TOOLS_LINUX_DIR")

set(
    LINUX_TOOLS

    ExploitTemplate
)

foreach(TOOL_DIR ${LINUX_TOOLS})
    add_executable(${TOOL_DIR} ${PWNLIB_TOOLS_LINUX_DIR}/${TOOL_DIR}/main.cpp)
    add_dependencies(${TOOL_DIR} ${CMAKE_PROJECT_NAME})

    target_include_directories(${TOOL_DIR} PUBLIC $<TARGET_PROPERTY:${CMAKE_PROJECT_NAME},INCLUDE_DIRECTORIES>)
    target_link_libraries(${TOOL_DIR} PRIVATE $<TARGET_LINKER_FILE:${CMAKE_PROJECT_NAME}>)

    install(TARGETS ${TOOL_DIR} DESTINATION Tools)
endforeach()
