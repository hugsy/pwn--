#
# Unit tests
#
set(PWNLIB_TEST_DIR ${PWNLIB_ROOT_DIR}/tests CACHE INTERNAL "PWNLIB_TEST_DIR")

enable_testing()

set(COMMON_TEST_DIR ${PWNLIB_TEST_DIR})

set(
    SOURCE_FILES

    ${COMMON_TEST_DIR}/main.cpp
    ${COMMON_TEST_DIR}/pwn_utils.cpp
    ${COMMON_TEST_DIR}/pwn_crypto.cpp
    ${COMMON_TEST_DIR}/pwn_assm_disasm.cpp
)

if(MSVC)
    set(TEST_DIR ${COMMON_TEST_DIR}/win32)
    set(
        SOURCE_FILES

        ${SOURCE_FILES}
        ${TEST_DIR}/pwn_win_system.cpp
        ${TEST_DIR}/pwn_win_process.cpp
        ${TEST_DIR}/pwn_win_thread.cpp
        ${TEST_DIR}/pwn_win_token.cpp
        ${TEST_DIR}/pwn_win_object.cpp
    )
else()
    set(TEST_DIR ${COMMON_TEST_DIR}/linux)
    set(
        SOURCE_FILES

        ${SOURCE_FILES}
        ${TEST_DIR}/pwn_linux_system.cpp
    )
endif(MSVC)

add_executable(tests ${SOURCE_FILES})
add_dependencies(tests pwn++)

set_target_properties(tests PROPERTIES CXX_STANDARD 20)
target_compile_features(tests PUBLIC cxx_std_20)

target_compile_options(tests PRIVATE $<TARGET_PROPERTY:${CMAKE_PROJECT_NAME},INTERFACE_COMPILE_OPTIONS>)
target_compile_definitions(tests PRIVATE $<TARGET_PROPERTY:${CMAKE_PROJECT_NAME},INTERFACE_COMPILE_DEFINITIONS>)
target_include_directories(tests PRIVATE ${TEST_DIR} $<TARGET_PROPERTY:${CMAKE_PROJECT_NAME},INCLUDE_DIRECTORIES>)

target_link_libraries(tests PRIVATE $<TARGET_LINKER_FILE:${CMAKE_PROJECT_NAME}> $<TARGET_PROPERTY:${CMAKE_PROJECT_NAME},INTERFACE_LINK_LIBRARIES>)
target_link_options(tests PRIVATE $<TARGET_PROPERTY:${CMAKE_PROJECT_NAME},INTERFACE_LINK_OPTIONS> /SUBSYSTEM:Console)

if(MSVC)
    target_compile_definitions(tests PRIVATE CATCH_CONFIG_NO_WINDOWS_SEH)
else()
    target_compile_definitions(tests PRIVATE _GNU_SOURCE=1)
endif(MSVC)

add_test(
    NAME tests
    COMMAND $<TARGET_FILE:tests>
)

add_custom_command(
    TARGET tests POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
    $<TARGET_FILE:pwn++> $<TARGET_FILE_DIR:tests>
)
