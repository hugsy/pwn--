#
# Unit tests
#
set(PWNLIB_TEST_DIR ${PWNLIB_ROOT_DIR}/tests CACHE INTERNAL "PWNLIB_TEST_DIR")

enable_testing()

set(TEST_CATEGORIES common)

if(MSVC)
    set(TEST_CATEGORIES ${TEST_CATEGORIES} win32)
else()
    set(TEST_CATEGORIES ${TEST_CATEGORIES} linux)
endif(MSVC)

foreach(CATEGORY ${TEST_CATEGORIES})
    set(EXE_NAME tests-${CATEGORY})
    set(DIR_NAME ${PWNLIB_TEST_DIR}/${CATEGORY})
    file(GLOB TEST_FILES ${DIR_NAME}/*.cpp)
    set(SOURCE_FILES ${TEST_FILES} ${PWNLIB_TEST_DIR}/main.cpp)

    add_executable(${EXE_NAME} ${SOURCE_FILES})
    add_dependencies(${EXE_NAME} ${CMAKE_PROJECT_NAME})

    set_target_properties(${EXE_NAME} PROPERTIES CXX_STANDARD 20)
    target_compile_features(${EXE_NAME} PUBLIC cxx_std_20)

    target_compile_options(${EXE_NAME} PRIVATE $<TARGET_PROPERTY:${CMAKE_PROJECT_NAME},INTERFACE_COMPILE_OPTIONS>)
    target_compile_definitions(${EXE_NAME} PRIVATE $<TARGET_PROPERTY:${CMAKE_PROJECT_NAME},INTERFACE_COMPILE_DEFINITIONS>)
    target_include_directories(${EXE_NAME} PRIVATE ${PWNLIB_TEST_DIR} ${DIR_NAME} $<TARGET_PROPERTY:${CMAKE_PROJECT_NAME},INCLUDE_DIRECTORIES>)

    target_link_libraries(${EXE_NAME} PRIVATE $<TARGET_LINKER_FILE:${CMAKE_PROJECT_NAME}> $<TARGET_PROPERTY:${CMAKE_PROJECT_NAME},INTERFACE_LINK_LIBRARIES>)
    target_link_options(${EXE_NAME} PRIVATE $<TARGET_PROPERTY:${CMAKE_PROJECT_NAME},INTERFACE_LINK_OPTIONS> /SUBSYSTEM:Console)

    if(MSVC)
        target_compile_definitions(${EXE_NAME} PRIVATE CATCH_CONFIG_NO_WINDOWS_SEH)
    else()
        target_compile_definitions(${EXE_NAME} PRIVATE _GNU_SOURCE=1)
    endif(MSVC)

    add_test(NAME ${EXE_NAME} COMMAND $<TARGET_FILE:${EXE_NAME}>)

    add_custom_command(TARGET ${EXE_NAME} POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
        $<TARGET_FILE:${CMAKE_PROJECT_NAME}> $<TARGET_FILE_DIR:${EXE_NAME}>
    )
endforeach()
