project(Assembly CXX)
message(STATUS "Configuring module '${PROJECT_NAME}'")

set(PROJECT_DIR ${PWNLIB_MODULE_DIR}/${PROJECT_NAME})
set(INTERFACE_DIR ${PROJECT_DIR}/Include)
set(SOURCE_DIR ${PROJECT_DIR}/Source)
set(HEADER_DIR ${SOURCE_DIR}/Include)
set(TEST_DIR ${PROJECT_DIR}/Tests)

add_library(${PROJECT_NAME} STATIC)
add_dependencies(${PROJECT_NAME} PWN::Common)
add_library(PWN::Assembly ALIAS ${PROJECT_NAME})

if(PWN_INCLUDE_DISASSEMBLER)
    list(APPEND SOURCE_FILES ${SOURCE_DIR}/Disassembler.cpp)
    target_compile_definitions(${PROJECT_NAME} PUBLIC PWN_INCLUDE_DISASSEMBLER)

    if(PWN_DISASSEMBLE_X86)
        target_compile_definitions(${PROJECT_NAME} PUBLIC PWN_DISASSEMBLE_X86)
        target_include_directories(${PROJECT_NAME} PRIVATE $<TARGET_PROPERTY:PWN::Deps::Zydis,INCLUDE_DIRECTORIES>)
        target_link_libraries(${PROJECT_NAME} PUBLIC PWN::Deps::Zydis)
    endif(PWN_DISASSEMBLE_X86)

    if(PWN_DISASSEMBLE_ARM64)
        target_compile_definitions(${PROJECT_NAME} PUBLIC PWN_DISASSEMBLE_ARM64)
        target_include_directories(${PROJECT_NAME} PRIVATE $<TARGET_PROPERTY:PWN::Deps::BinjaArm64,INCLUDE_DIRECTORIES>)
        target_link_libraries(${PROJECT_NAME} PUBLIC PWN::Deps::BinjaArm64)
    endif(PWN_DISASSEMBLE_ARM64)
endif(PWN_INCLUDE_DISASSEMBLER)

target_sources(${PROJECT_NAME} PRIVATE ${SOURCE_FILES})
target_include_directories(${PROJECT_NAME} PUBLIC ${INTERFACE_DIR})
target_link_libraries(${PROJECT_NAME} PUBLIC PWN::Common)

install(DIRECTORY ${INTERFACE_DIR} DESTINATION ${CMAKE_PROJECT_NAME})

if(PWN_BUILD_TESTING)
    add_subdirectory(Tests)
endif(PWN_BUILD_TESTING)
