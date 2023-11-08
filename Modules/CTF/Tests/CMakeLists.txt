enable_testing()
set(TEST_EXECUTABLE_NAME tests_pwn_${PROJECT_NAME})
set(SOURCE_FILES

    ${TEST_DIR}/main.cpp
)

if(WIN32)
    set(SOURCE_FILES

        ${SOURCE_FILES}
        ${TEST_DIR}/pwn_ctf_process_win.cpp
        ${TEST_DIR}/pwn_ctf_remote_win.cpp
    )
    set(DEPS PWN::Process PWN::Network)
else()
endif(WIN32)

add_executable(${TEST_EXECUTABLE_NAME} ${SOURCE_FILES})
add_executable(PWN::Tests::${PROJECT_NAME} ALIAS ${TEST_EXECUTABLE_NAME})
add_dependencies(${TEST_EXECUTABLE_NAME} PWN::Deps::Catch2 PWN::${PROJECT_NAME} ${DEPS})
target_link_libraries(${TEST_EXECUTABLE_NAME} PUBLIC Catch2::Catch2WithMain PWN::${PROJECT_NAME} ${DEPS})

if(WIN32)
    target_link_options(${TEST_EXECUTABLE_NAME} PUBLIC /SUBSYSTEM:Console)
endif(WIN32)

add_test(NAME ${TEST_EXECUTABLE_NAME} COMMAND $<TARGET_FILE:${TEST_EXECUTABLE_NAME}>)
set_tests_properties(${TEST_EXECUTABLE_NAME} PROPERTIES LABELS Common LABELS CTF)
install(FILES $<TARGET_FILE:${TEST_EXECUTABLE_NAME}> DESTINATION Tests)
