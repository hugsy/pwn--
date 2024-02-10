include(FetchContent)

FetchContent_Declare(
    Deps_Mk_Clib
    GIT_REPOSITORY https://github.com/MarekKnapek/mk_clib
    GIT_TAG c967117af337a3326e607125314ca51458ddea84
)
FetchContent_MakeAvailable(Deps_Mk_Clib)

message(STATUS "Using MkCLib in '${deps_mk_clib_SOURCE_DIR}'")

set(SOURCE_DIR ${deps_mk_clib_SOURCE_DIR}/mk_clib/src)

find_program(M4_EXECUTABLE m4 HINTS "C:/Program Files (x86)/GnuWin32/bin")
if(NOT M4_EXECUTABLE)
    message(FATAL_ERROR "m4 macro processor not found")
endif()

set(M4_FILES
    # mk_clib_readme.md
    mk_lang_bui_inl_defd
    mk_lang_bui_inl_defu
    mk_lang_bui_inl_filec
    mk_lang_bui_inl_fileh
    mk_lib_crypto_alg_aes_128
    mk_lib_crypto_alg_aes_192
    mk_lib_crypto_alg_aes_256
    mk_lib_crypto_mode_cbc_aes_128
    mk_lib_crypto_mode_cbc_aes_192
    mk_lib_crypto_mode_cbc_aes_256
    mk_lib_crypto_mode_cbc_serpent
    mk_lib_crypto_mode_cfb_128_aes_128
    mk_lib_crypto_mode_cfb_128_aes_192
    mk_lib_crypto_mode_cfb_128_aes_256
    mk_lib_crypto_mode_cfb_128_serpent
    mk_lib_crypto_mode_cfb_8_aes_128
    mk_lib_crypto_mode_cfb_8_aes_192
    mk_lib_crypto_mode_cfb_8_aes_256
    mk_lib_crypto_mode_cfb_8_serpent
    mk_lib_crypto_mode_ctr_be_aes_128
    mk_lib_crypto_mode_ctr_be_aes_192
    mk_lib_crypto_mode_ctr_be_aes_256
    mk_lib_crypto_mode_ctr_be_serpent
    mk_lib_crypto_mode_ecb_aes_128
    mk_lib_crypto_mode_ecb_aes_192
    mk_lib_crypto_mode_ecb_aes_256
    mk_lib_crypto_mode_ecb_serpent
    mk_lib_crypto_mode_ofb_aes_128
    mk_lib_crypto_mode_ofb_aes_192
    mk_lib_crypto_mode_ofb_aes_256
    mk_lib_crypto_mode_ofb_serpent
    mk_sl_cui_inl_defd
    mk_sl_cui_inl_defu
    mk_sl_cui_inl_filec
    mk_sl_cui_inl_fileh
)

file(GLOB MK_CLIB_SOURCE_FILES ${SOURCE_DIR}/*.c)
add_library(Deps_Mk_Clib_Crypto STATIC ${MK_CLIB_SOURCE_FILES})
target_include_directories(Deps_Mk_Clib_Crypto PUBLIC ${SOURCE_DIR})
set_property(TARGET Deps_Mk_Clib_Crypto PROPERTY CXX_STANDARD 23)
target_compile_definitions(Deps_Mk_Clib_Crypto PUBLIC mk_lang_jumbo_want=0)
target_compile_features(Deps_Mk_Clib_Crypto PUBLIC cxx_std_23)

foreach(M4_FILE ${M4_FILES})
    set(INFILE ${SOURCE_DIR}/${M4_FILE}.h.m4)
    set(OUTFILE ${SOURCE_DIR}/${M4_FILE}.h)

    add_custom_command(
        TARGET Deps_Mk_Clib_Crypto
        PRE_BUILD
        COMMAND ${M4_EXECUTABLE} -I ${SOURCE_DIR} -- ${INFILE} > ${OUTFILE}
        COMMENT "Generating file '${M4_FILE}' with M4"
    )
endforeach()

add_library(PWN::Deps::MkClib::Crypto ALIAS Deps_Mk_Clib_Crypto)
