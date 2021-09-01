set(PWNLIB_DIR ../../../src)
set(PWNLIB_HEADER_DIR ${PWNLIB_DIR}/inc)
set(SOURCE_FILES main.cpp)

add_executable(HexdumpFile ${SOURCE_FILES})
target_include_directories(HexdumpFile PUBLIC ${PWNLIB_HEADER_DIR})
target_link_libraries(HexdumpFile pwn++)

