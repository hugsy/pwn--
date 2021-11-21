set(PWNLIB_DIR ../../../src)
set(PWNLIB_HEADER_DIR ${PWNLIB_DIR}/inc)
set(SOURCE_FILES main.cpp)

add_executable(ProcessReparent ${SOURCE_FILES})
target_include_directories(ProcessReparent PUBLIC ${PWNLIB_HEADER_DIR})
target_link_libraries(ProcessReparent pwn++)

