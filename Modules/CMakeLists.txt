set(PWNLIB_MODULE_DIR ${PWNLIB_ROOT_DIR}/Modules CACHE INTERNAL "PWNLIB_MODULE_DIR")

#
# Set up the variables exported to constants.hpp
#
set(PWN_LIBRARY_NAME ${PROJECT_NAME})
set(PWN_LIBRARY_AUTHOR ${PROJECT_AUTHOR})
set(PWN_LIBRARY_LICENSE ${PROJECT_LICENSE})
set(PWN_LIBRARY_VERSION_MAJOR ${PROJECT_VERSION_MAJOR})
set(PWN_LIBRARY_VERSION_MINOR ${PROJECT_VERSION_MINOR})
set(PWN_LIBRARY_VERSION_PATCH ${PROJECT_VERSION_PATCH})
set(PWN_LIBRARY_VERSION_RELEASE "Standalone")
set(PWN_LIBRARY_VERSION ${PROJECT_VERSION})
set(PWN_BUILD_ARCHITECTURE ${CMAKE_SYSTEM_PROCESSOR})
set(PWN_BUILD_OS ${CMAKE_SYSTEM_NAME})

#
# Print out cmake compile info
#
message(STATUS "PWN_LOG_USE_COLOR                      ${PWN_LOG_USE_COLOR}")
message(STATUS "PWN_BUILD_CRYPTO                       ${PWN_BUILD_CRYPTO}")
message(STATUS "PWN_BUILD_TOOLKIT                      ${PWN_BUILD_TOOLKIT}")
message(STATUS "PWN_BUILD_TESTING                      ${PWN_BUILD_TESTING}")
message(STATUS "PWN_BUILD_DOCS                         ${PWN_BUILD_DOCS}")
message(STATUS "PWN_INCLUDE_DISASSEMBLER               ${PWN_INCLUDE_DISASSEMBLER}")

if(PWN_INCLUDE_DISASSEMBLER)
    message(STATUS "PWN_INCLUDE_DISASSEMBLER_X86                 ${PWN_DISASSEMBLE_X86}")
    message(STATUS "PWN_INCLUDE_DISASSEMBLER_ARM64               ${PWN_DISASSEMBLE_ARM64}")
endif()

#
# If `git` is found, declare the branch/commit hash for debugging
#
find_package(Git)

if(Git_FOUND)
    execute_process(
        COMMAND ${GIT_EXECUTABLE} rev-parse --abbrev-ref HEAD
        OUTPUT_VARIABLE GIT_RELEASE_BRANCH
        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
    )
    execute_process(
        COMMAND ${GIT_EXECUTABLE} log -n 1 --pretty=format:%t
        OUTPUT_VARIABLE GIT_RELEASE_COMMIT
        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
    )

    string(STRIP "${GIT_RELEASE_BRANCH}" GIT_RELEASE_BRANCH)
    string(STRIP "${GIT_RELEASE_COMMIT}" GIT_RELEASE_COMMIT)

    set(PWN_LIBRARY_VERSION_RELEASE "${GIT_RELEASE_BRANCH}:${GIT_RELEASE_COMMIT}")
endif()

#
# Compile all modules
#
foreach(MODULE ${PWN_MODULES})
    add_subdirectory(${MODULE})
endforeach()
