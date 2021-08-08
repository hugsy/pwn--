#
# Unit tests
#

set(COMMON_TEST_DIR ${CMAKE_CURRENT_LIST_DIR})

set(TEST_DIR ${COMMON_TEST_DIR}/win)
set(
    SOURCE_FILES
    ${COMMON_TEST_DIR}/main.cpp
    ${COMMON_TEST_DIR}/pwn_utils.cpp
    ${COMMON_TEST_DIR}/pwn_crypto.cpp
    ${COMMON_TEST_DIR}/pwn_assm_disasm.cpp
    ${TEST_DIR}/pwn_win_system.cpp
    ${TEST_DIR}/pwn_win_thread.cpp
)

add_executable(unit_tests ${SOURCE_FILES})
target_include_directories(unit_tests PUBLIC ${TEST_DIR}/)
target_link_libraries(unit_tests pwn++)