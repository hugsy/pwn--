set(PWNLIB_DIR ../../../src)
set(PWNLIB_HEADER_DIR ${PWNLIB_DIR}/inc)
set(SOURCE_FILES main.cpp)

add_executable(AppContainMe ${SOURCE_FILES})
target_include_directories(AppContainMe PUBLIC ${PWNLIB_HEADER_DIR})
target_link_libraries(AppContainMe pwn++)

