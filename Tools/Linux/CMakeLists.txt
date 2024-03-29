#
# Build Linux test tools
#

set(PWNLIB_TOOLS_LINUX_DIR ${PWNLIB_ROOT_DIR}/Tools/Linux CACHE INTERNAL "PWNLIB_TOOLS_LINUX_DIR")

set(
    LINUX_TOOLS

    ExploitTemplate
)

foreach(TOOL_DIR ${LINUX_TOOLS})
    file(GLOB SOURCE_FILES ${PWNLIB_TOOLS_LINUX_DIR}/${TOOL_DIR}/*.cpp ${PWNLIB_TOOLS_LINUX_DIR}/${TOOL_DIR}/*.asm)
    add_executable(${TOOL_DIR} ${SOURCE_FILES})
    add_dependencies(${TOOL_DIR} ${CMAKE_PROJECT_NAME})
    target_compile_features(${TOOL_DIR} PUBLIC cxx_std_23)
    set_target_properties(${TOOL_DIR} PROPERTIES CXX_STANDARD 23)

    target_compile_definitions(${TOOL_DIR} PUBLIC PWN_BUILD_FOR_LINUX)
    target_compile_options(${TOOL_DIR}
        PUBLIC
        $<$<CONFIG:Debug>:-fsanitize=address>
    )

    target_compile_options(${TOOL_DIR} PRIVATE $<TARGET_PROPERTY:${CMAKE_PROJECT_NAME},INTERFACE_COMPILE_OPTIONS>)
    target_compile_definitions(${TOOL_DIR} PRIVATE $<TARGET_PROPERTY:${CMAKE_PROJECT_NAME},INTERFACE_COMPILE_DEFINITIONS>)
    target_include_directories(${TOOL_DIR} PRIVATE $<TARGET_PROPERTY:${CMAKE_PROJECT_NAME},INTERFACE_INCLUDE_DIRECTORIES> ${PWNLIB_ROOT_DIR}/Deps/argparse)
    target_link_libraries(${TOOL_DIR} PRIVATE ${CMAKE_PROJECT_NAME} $<TARGET_PROPERTY:${CMAKE_PROJECT_NAME},INTERFACE_LINK_LIBRARIES>)
    target_link_options(${TOOL_DIR} PRIVATE $<TARGET_PROPERTY:${CMAKE_PROJECT_NAME},INTERFACE_LINK_OPTIONS>)

    install(TARGETS ${TOOL_DIR} DESTINATION Tools)
endforeach()
