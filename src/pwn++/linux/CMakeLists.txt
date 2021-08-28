#
# Linux specific definitions
#
set(HEADER_DIR ${COMMON_HEADER_DIR}/linux)
set(
    HEADER_FILES
    ${COMMON_HEADER_FILES}
    ${HEADER_DIR}/system.hpp
)

set(SOURCE_DIR ${COMMON_SOURCE_DIR}/linux)
set(
    SOURCE_FILES
    ${COMMON_SOURCE_FILES}
    ${SOURCE_DIR}/system.cpp
)

add_library(pwn++ SHARED ${SOURCE_FILES})

# target_compile_options(pwn++ PRIVATE -Wno-ignored-optimization-argument)
target_compile_features(pwn++ PRIVATE cxx_std_17)
set_property(TARGET pwn++ PROPERTY CXX_STANDARD 17)

add_compile_definitions(DEBUG)

target_include_directories(pwn++ PUBLIC ${COMMON_HEADER_DIR} ${HEADER_DIR})
target_include_directories(pwn++ PRIVATE ${COMMON_SOURCE_DIR} ${SOURCE_DIR})

target_link_libraries(
    pwn++
    PRIVATE
    pthread
    dl
)