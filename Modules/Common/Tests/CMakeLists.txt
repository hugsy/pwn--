enable_testing()
set(TEST_DIR ${CMAKE_CURRENT_LIST_DIR})
list(APPEND TEST_SOURCE_FILES

    # Test cases
    ${TEST_DIR}/tests_pwn_common.cpp

    # Performance tests
    ${TEST_DIR}/perf_pwn_common.cpp
)

foreach(SOURCE_FILE ${TEST_SOURCE_FILES})
    cmake_path(GET SOURCE_FILE STEM TEST_EXECUTABLE_NAME)
    add_executable(${TEST_EXECUTABLE_NAME} ${SOURCE_FILE})
    add_dependencies(${TEST_EXECUTABLE_NAME} PWN::Deps::Catch2 PWN::${PROJECT_NAME})
    target_link_libraries(${TEST_EXECUTABLE_NAME} PUBLIC PWN::Deps::Catch2 PWN::${PROJECT_NAME})

    if(WIN32)
        target_link_options(${TEST_EXECUTABLE_NAME} PUBLIC /SUBSYSTEM:Console)
    endif(WIN32)

    add_test(NAME ${TEST_EXECUTABLE_NAME} COMMAND $<TARGET_FILE:${TEST_EXECUTABLE_NAME}>)
    set_tests_properties(${TEST_EXECUTABLE_NAME} PROPERTIES LABELS Common LABELS Version)
    install(FILES $<TARGET_FILE:${TEST_EXECUTABLE_NAME}> DESTINATION Tests)
endforeach()
