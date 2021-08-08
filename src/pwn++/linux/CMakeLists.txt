#
# Linux specific definitions
#
set(HEADER_DIR ${COMMON_HEADER_DIR}/linux)
set(
    HEADER_FILES
    ${COMMON_HEADER_FILES}
    # ${HEADER_DIR}/process.hpp
)

set(SOURCE_DIR ${COMMON_SOURCE_DIR}/linux)
set(
    SOURCE_FILES
    ${COMMON_SOURCE_FILES}
    # ${SOURCE_DIR}/process.cpp
)

add_library(pwn++ SHARED ${SOURCE_FILES})

add_compile_definitions(-fPIC -shared)

target_include_directories(pwn++ PUBLIC ${COMMON_HEADER_DIR} ${HEADER_DIR})
target_include_directories(pwn++ PRIVATE ${COMMON_SOURCE_DIR} ${SOURCE_DIR})

target_link_libraries(
    pwn++
    PRIVATE
    pthread
    dl
)