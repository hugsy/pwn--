#
# Unit tests
#

set(COMMON_TEST_DIR ${CMAKE_CURRENT_LIST_DIR})

set(
    SOURCE_FILES
    ${COMMON_TEST_DIR}/main.cpp
    ${COMMON_TEST_DIR}/pwn_utils.cpp
    ${COMMON_TEST_DIR}/pwn_crypto.cpp
    ${COMMON_TEST_DIR}/pwn_assm_disasm.cpp
)


if(MSVC)
    set(TEST_DIR ${COMMON_TEST_DIR}/win)
    set(
        SOURCE_FILES
        ${SOURCE_FILES}
        ${TEST_DIR}/pwn_win_system.cpp
        ${TEST_DIR}/pwn_win_thread.cpp
    )

    add_compile_definitions(_UNICODE)
    add_compile_definitions(UNICODE)
else()
    set(TEST_DIR ${COMMON_TEST_DIR}/linux)
    set(
        SOURCE_FILES
        ${SOURCE_FILES}
        ${TEST_DIR}/pwn_linux_system.cpp
    )
endif(MSVC)

if(NOT INCLUDE_DISASSEMBLER)
    add_compile_definitions(PWN_NO_DISASSEMBLER)
endif()

if(NOT INCLUDE_ASSEMBLER)
    add_compile_definitions(PWN_NO_ASSEMBLER)
endif()

add_executable(unit_tests ${SOURCE_FILES})
target_include_directories(unit_tests PUBLIC ${TEST_DIR}/)
target_link_libraries(unit_tests pwn++)
