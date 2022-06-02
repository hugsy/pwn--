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
        ${TEST_DIR}/pwn_win_thread.cpp
    )

    add_compile_definitions(_UNICODE UNICODE)
else()
    set(TEST_DIR ${COMMON_TEST_DIR}/linux)
    set(
        SOURCE_FILES

        ${SOURCE_FILES}
        ${TEST_DIR}/pwn_linux_system.cpp
    )

    add_compile_definitions(_GNU_SOURCE=1)
endif(MSVC)


if(NOT PWN_INCLUDE_DISASSEMBLER)
    add_compile_definitions(PWN_NO_DISASSEMBLER)
endif()


if(NOT PWN_INCLUDE_ASSEMBLER)
    add_compile_definitions(PWN_NO_ASSEMBLER)
endif()

add_executable(tests ${SOURCE_FILES})
add_dependencies(tests pwn++)

add_test(
    NAME tests
    COMMAND $<TARGET_FILE:tests>
)

set_target_properties(
    tests
    PROPERTIES
    CXX_STANDARD 23
)

target_compile_features(tests PRIVATE cxx_std_23)
target_include_directories(tests PUBLIC ${TEST_DIR} $<TARGET_PROPERTY:pwn++,INCLUDE_DIRECTORIES>)
target_link_libraries(tests PRIVATE $<TARGET_LINKER_FILE:pwn++>)

add_custom_command(
    TARGET tests POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
        $<TARGET_FILE:pwn++> $<TARGET_FILE_DIR:tests>
)
