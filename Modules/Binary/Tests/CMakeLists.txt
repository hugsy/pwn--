enable_testing()
set(TEST_BINARY_PE tests_pwn_${PROJECT_NAME})
list(APPEND SOURCE_FILES

    ${TEST_DIR}/main.cpp
    ${TEST_DIR}/pwn_binary_pe.cpp
)

set(DEPS PWN::Common PWN::FileSystem)
file(GLOB DLL_TEST_FILES "C:/Windows/System32/*.dll")

add_executable(${TEST_BINARY_PE} ${SOURCE_FILES})
add_executable(PWN::Tests::${PROJECT_NAME}::PE ALIAS ${TEST_BINARY_PE})
add_dependencies(${TEST_BINARY_PE} PWN::Deps::Catch2 PWN::${PROJECT_NAME} ${DEPS})
target_link_libraries(${TEST_BINARY_PE} PUBLIC Catch2::Catch2WithMain PWN::${PROJECT_NAME} ${DEPS})
target_link_options(${TEST_BINARY_PE} PUBLIC /SUBSYSTEM:Console)
add_test(NAME ${TEST_BINARY_PE} COMMAND $<TARGET_FILE:${TEST_BINARY_PE}>)
set_tests_properties(${TEST_BINARY_PE} PROPERTIES LABELS Common LABELS ${PROJECT_NAME})
install(FILES $<TARGET_FILE:${TEST_BINARY_PE}> DESTINATION Tests)
