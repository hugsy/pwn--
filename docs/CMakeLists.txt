find_package(Doxygen REQUIRED)

set(VERSIONS Win32 Linux)
set(PWN_DOCS_ROOT_DIR "${PWNLIB_ROOT_DIR}/Docs")
set(PWN_SRC_ROOT_DIR "${PWNLIB_ROOT_DIR}/Modules")
set(PWN_DOCS_CSS_ROOT_DIR "${PWN_DOCS_ROOT_DIR}/css")
set(DOXYFILE_IN ${PWN_DOCS_ROOT_DIR}/Doxyfile.in)
set(DOXYGEN_CSS "${PWN_DOCS_CSS_ROOT_DIR}/doxygen-awesome.css ${PWN_DOCS_CSS_ROOT_DIR}/doxygen-awesome-sidebar-only.css")

foreach(Module ${PWN_MODULES})
    set(PWN_SRC_WIN32_ROOT_DIR "${PWN_SRC_ROOT_DIR}/${Module}")
    set(PWN_DOCS_API_ROOT_DIR "${PWN_DOCS_ROOT_DIR}/api/${Module}")

    file(GLOB PWN_PUBLIC_COMMON_HEADERS ${PWN_SRC_ROOT_DIR}/*.hpp)
    file(GLOB_RECURSE PWN_PUBLIC_WIN32_HEADERS ${PWN_SRC_WIN32_ROOT_DIR}/*.hpp)

    set(PWN_PUBLIC_HEADERS ${PWN_PUBLIC_COMMON_HEADERS} ${PWN_PUBLIC_WIN32_HEADERS})

    set(DOXYGEN_INPUT_DIR "${PWN_SRC_ROOT_DIR} ${PWN_SRC_WIN32_ROOT_DIR}")
    set(DOXYGEN_OUTPUT_DIR ${PWN_DOCS_API_ROOT_DIR})
    set(DOXYGEN_INDEX_FILE ${DOXYGEN_OUTPUT_DIR}/html/index.html)
    set(DOXYFILE_OUT ${PWN_DOCS_ROOT_DIR}/Doxyfile.${Module})

    configure_file(${DOXYFILE_IN} ${DOXYFILE_OUT} @ONLY)

    add_custom_command(
        OUTPUT ${DOXYGEN_INDEX_FILE}
        DEPENDS ${PWN_PUBLIC_HEADERS}
        COMMAND ${DOXYGEN_EXECUTABLE} ${DOXYFILE_OUT}
        MAIN_DEPENDENCY ${DOXYFILE_OUT} ${DOXYFILE_IN}
        WORKING_DIRECTORY ${PWN_DOCS_API_ROOT_DIR}
        COMMENT "Generating API Docs for ${Module}")

    add_custom_target(Doxygen-${Module} ALL DEPENDS ${DOXYGEN_INDEX_FILE})

    file(
        GENERATE
        OUTPUT ${DOXYGEN_OUTPUT_DIR}/index.html
        CONTENT "<img src='meh' onerror='var base=window.location.href.replace(/\\\/#\\\/.*/g,\"\"); window.location.href=base+\"/api/${Module}/html/index.html\";' >"
        TARGET Doxygen-${Module}
    )
endforeach()

add_custom_target(Doxygen ALL DEPENDS Doxygen-Win32 Doxygen-Linux)
