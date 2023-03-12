project(Assembly CXX)
message(STATUS "Configuring module '${PROJECT_NAME}'")

set(PROJECT_DIR ${PWNLIB_MODULE_DIR}/${PROJECT_NAME})
set(INTERFACE_DIR ${PROJECT_DIR}/Include)
set(SOURCE_DIR ${PROJECT_DIR}/Source)
set(HEADER_DIR ${SOURCE_DIR}/Include)
set(TEST_DIR ${PROJECT_DIR}/Tests)
list(APPEND SOURCE_FILES ${SOURCE_DIR}/Disassembler.cpp)

add_library(${PROJECT_NAME} STATIC ${SOURCE_FILES})
add_dependencies(${PROJECT_NAME} PWN::Common)
add_library(PWN::Assembly ALIAS ${PROJECT_NAME})
target_include_directories(${PROJECT_NAME} PUBLIC ${INTERFACE_DIR} PRIVATE $<TARGET_PROPERTY:PWN::Deps::BinjaArm64,INCLUDE_DIRECTORIES>)
target_compile_definitions(${PROJECT_NAME} PUBLIC PWN_INCLUDE_DISASSEMBLER PWN_DISASSEMBLE_X86 PWN_DISASSEMBLE_ARM64)
target_link_libraries(${PROJECT_NAME} PUBLIC PWN::Common PWN::Deps::Zydis PWN::Deps::BinjaArm64)

install(DIRECTORY ${INTERFACE_DIR} DESTINATION ${CMAKE_PROJECT_NAME})

if(PWN_BUILD_TESTING)
    add_subdirectory(Tests)
endif(PWN_BUILD_TESTING)
