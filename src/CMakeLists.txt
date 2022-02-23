if(NOT INCLUDE_BACKDOOR)
    add_compile_definitions(PWN_NO_BACKDOOR)
endif()

if(NOT DISABLE_LOG_COLOR)
    add_compile_definitions(PWN_LOG_USE_COLOR)
endif()


set(PWNLIB_SRC_DIR ${PWNLIB_ROOT_DIR}/src)


#
# Build pwn++ library
#
add_subdirectory(pwn++)


#
# Build unit tests
#
add_subdirectory(tests)

