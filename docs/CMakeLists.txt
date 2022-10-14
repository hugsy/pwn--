find_package(Doxygen REQUIRED)

set(VERSIONS win32 linux)
set(PWN_DOCS_ROOT_DIR "${PWNLIB_ROOT_DIR}/docs")
set(PWN_SRC_ROOT_DIR "${PWNLIB_ROOT_DIR}/src/inc")
set(PWN_DOCS_CSS_ROOT_DIR "${PWN_DOCS_ROOT_DIR}/css")
set(DOXYFILE_IN ${PWN_DOCS_ROOT_DIR}/Doxyfile.in)
set(DOXYGEN_CSS "${PWN_DOCS_CSS_ROOT_DIR}/doxygen-awesome.css ${PWN_DOCS_CSS_ROOT_DIR}/doxygen-awesome-sidebar-only.css")

foreach(OS ${VERSIONS})
    set(PWN_DOCS_API_ROOT_DIR "${PWN_DOCS_ROOT_DIR}/api/${OS}")
    set(PWN_SRC_WIN32_ROOT_DIR "${PWN_SRC_ROOT_DIR}/${OS}")

    file(GLOB PWN_PUBLIC_COMMON_HEADERS ${PWN_SRC_ROOT_DIR}/*.hpp)
    file(GLOB_RECURSE PWN_PUBLIC_WIN32_HEADERS ${PWN_SRC_WIN32_ROOT_DIR}/*.hpp)

    set(PWN_PUBLIC_HEADERS ${PWN_PUBLIC_COMMON_HEADERS} ${PWN_PUBLIC_WIN32_HEADERS})

    set(DOXYGEN_INPUT_DIR "${PWN_SRC_ROOT_DIR} ${PWN_SRC_WIN32_ROOT_DIR}")
    set(DOXYGEN_OUTPUT_DIR ${PWN_DOCS_API_ROOT_DIR})
    set(DOXYGEN_INDEX_FILE ${DOXYGEN_OUTPUT_DIR}/html/index.html)
    set(DOXYFILE_OUT ${PWN_DOCS_ROOT_DIR}/Doxyfile.${OS})

    configure_file(${DOXYFILE_IN} ${DOXYFILE_OUT} @ONLY)

    add_custom_command(
        OUTPUT ${DOXYGEN_INDEX_FILE}
        DEPENDS ${PWN_PUBLIC_HEADERS}
        COMMAND ${DOXYGEN_EXECUTABLE} ${DOXYFILE_OUT}
        MAIN_DEPENDENCY ${DOXYFILE_OUT} ${DOXYFILE_IN}
        WORKING_DIRECTORY ${PWN_DOCS_API_ROOT_DIR}
        COMMENT "Generating API Docs for ${OS}")

    add_custom_target(Doxygen-${OS} ALL DEPENDS ${DOXYGEN_INDEX_FILE})

    file(
        GENERATE
        OUTPUT ${DOXYGEN_OUTPUT_DIR}/index.html
        CONTENT "<img src='meh' onerror='var base=window.location.href.replace(/\\\/#\\\/.*/g,\"\"); window.location.href=base+\"/api/${OS}/html/index.html\";' >"
        TARGET Doxygen-${OS}
    )
endforeach()

add_custom_target(Doxygen ALL DEPENDS Doxygen-win32 Doxygen-linux)
