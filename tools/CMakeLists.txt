#
# Build test tools
#
set(PWNLIB_TOOLS_DIR ${PWNLIB_ROOT_DIR}/tools CACHE INTERNAL "PWNLIB_TOOLS_DIR")

if (WIN32)
    add_subdirectory(win32)
else()
    add_subdirectory(linux)
endif(WIN32)
