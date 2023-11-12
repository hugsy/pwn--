project(System CXX)
message(STATUS "Configuring module '${PROJECT_NAME}'")

set(PROJECT_DIR ${PWNLIB_MODULE_DIR}/${PROJECT_NAME})
set(INTERFACE_DIR ${PROJECT_DIR}/Include)
set(SOURCE_DIR ${PROJECT_DIR}/Source)
set(HEADER_DIR ${SOURCE_DIR}/Include)
set(TEST_DIR ${PROJECT_DIR}/Tests)

if(WIN32)
    set(SOURCE_FILES
        ${SOURCE_DIR}/Win32/System.cpp
        ${SOURCE_DIR}/Win32/ObjectManager.cpp
    )
    set(DEPS PWN::Common PWN::Symbols)
else()
    set(SOURCE_FILES
        ${SOURCE_DIR}/Linux/System.cpp
    )
    set(DEPS PWN::Common)
endif()

add_library(${PROJECT_NAME} STATIC ${SOURCE_FILES})
add_dependencies(${PROJECT_NAME} ${DEPS})
add_library(PWN::${PROJECT_NAME} ALIAS ${PROJECT_NAME})
target_include_directories(${PROJECT_NAME} PUBLIC ${INTERFACE_DIR} PRIVATE ${HEADER_DIR})
target_compile_definitions(${PROJECT_NAME} PUBLIC)
target_link_libraries(${PROJECT_NAME} PUBLIC ${DEPS})

if(WIN32)
    target_link_libraries(${PROJECT_NAME} PUBLIC AdvApi32.lib)
endif(WIN32)

install(DIRECTORY ${INTERFACE_DIR} DESTINATION ${CMAKE_PROJECT_NAME})

if(PWN_BUILD_TESTING)
    include(CTest)
    add_subdirectory(Tests)
endif(PWN_BUILD_TESTING)
