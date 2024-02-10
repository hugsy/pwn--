include(FetchContent)

FetchContent_Declare(
    Deps_Mk_Clib
    GIT_REPOSITORY https://github.com/MarekKnapek/mk_clib
    GIT_TAG c967117af337a3326e607125314ca51458ddea84
)
FetchContent_MakeAvailable(Deps_Mk_Clib)

message(STATUS "Using MkCLib in '${deps_mk_clib_SOURCE_DIR}'")

set(MK_CLIB_SOURCE_DIR ${deps_mk_clib_SOURCE_DIR}/mk_clib/src)

find_program(M4_EXECUTABLE m4 HINTS "C:/Program Files (x86)/GnuWin32/bin")
if(NOT M4_EXECUTABLE)
    message(FATAL_ERROR "m4 macro processor not found")
endif()

add_custom_target(
    Deps_Mk_Clib_Crypto_M4PreBuild
    COMMAND ${M4_EXECUTABLE} -Q -I ${MK_CLIB_SOURCE_DIR} mk_lang_bui_inl_defd.h.m4                  > mk_lang_bui_inl_defd.h
    COMMAND ${M4_EXECUTABLE} -Q -I ${MK_CLIB_SOURCE_DIR} mk_lang_bui_inl_defu.h.m4                  > mk_lang_bui_inl_defu.h
    COMMAND ${M4_EXECUTABLE} -Q -I ${MK_CLIB_SOURCE_DIR} mk_lang_bui_inl_filec.h.m4                 > mk_lang_bui_inl_filec.h
    COMMAND ${M4_EXECUTABLE} -Q -I ${MK_CLIB_SOURCE_DIR} mk_lang_bui_inl_fileh.h.m4                 > mk_lang_bui_inl_fileh.h
    COMMAND ${M4_EXECUTABLE} -Q -I ${MK_CLIB_SOURCE_DIR} mk_sl_cui_inl_defd.h.m4                    > mk_sl_cui_inl_defd.h
    COMMAND ${M4_EXECUTABLE} -Q -I ${MK_CLIB_SOURCE_DIR} mk_sl_cui_inl_defu.h.m4                    > mk_sl_cui_inl_defu.h
    COMMAND ${M4_EXECUTABLE} -Q -I ${MK_CLIB_SOURCE_DIR} mk_sl_cui_inl_filec.h.m4                   > mk_sl_cui_inl_filec.h
    COMMAND ${M4_EXECUTABLE} -Q -I ${MK_CLIB_SOURCE_DIR} mk_sl_cui_inl_fileh.h.m4                   > mk_sl_cui_inl_fileh.h
    COMMAND ${M4_EXECUTABLE} -Q -I ${MK_CLIB_SOURCE_DIR} mk_lib_crypto_alg_aes_128.h.m4             > mk_lib_crypto_alg_aes_128.h
    COMMAND ${M4_EXECUTABLE} -Q -I ${MK_CLIB_SOURCE_DIR} mk_lib_crypto_alg_aes_192.h.m4             > mk_lib_crypto_alg_aes_192.h
    COMMAND ${M4_EXECUTABLE} -Q -I ${MK_CLIB_SOURCE_DIR} mk_lib_crypto_alg_aes_256.h.m4             > mk_lib_crypto_alg_aes_256.h
    COMMAND ${M4_EXECUTABLE} -Q -I ${MK_CLIB_SOURCE_DIR} mk_lib_crypto_mode_cbc_aes_128.h.m4        > mk_lib_crypto_mode_cbc_aes_128.h
    COMMAND ${M4_EXECUTABLE} -Q -I ${MK_CLIB_SOURCE_DIR} mk_lib_crypto_mode_cbc_aes_192.h.m4        > mk_lib_crypto_mode_cbc_aes_192.h
    COMMAND ${M4_EXECUTABLE} -Q -I ${MK_CLIB_SOURCE_DIR} mk_lib_crypto_mode_cbc_aes_256.h.m4        > mk_lib_crypto_mode_cbc_aes_256.h
    COMMAND ${M4_EXECUTABLE} -Q -I ${MK_CLIB_SOURCE_DIR} mk_lib_crypto_mode_cbc_serpent.h.m4        > mk_lib_crypto_mode_cbc_serpent.h
    COMMAND ${M4_EXECUTABLE} -Q -I ${MK_CLIB_SOURCE_DIR} mk_lib_crypto_mode_cfb_128_aes_128.h.m4    > mk_lib_crypto_mode_cfb_128_aes_128.h
    COMMAND ${M4_EXECUTABLE} -Q -I ${MK_CLIB_SOURCE_DIR} mk_lib_crypto_mode_cfb_128_aes_192.h.m4    > mk_lib_crypto_mode_cfb_128_aes_192.h
    COMMAND ${M4_EXECUTABLE} -Q -I ${MK_CLIB_SOURCE_DIR} mk_lib_crypto_mode_cfb_128_aes_256.h.m4    > mk_lib_crypto_mode_cfb_128_aes_256.h
    COMMAND ${M4_EXECUTABLE} -Q -I ${MK_CLIB_SOURCE_DIR} mk_lib_crypto_mode_cfb_128_serpent.h.m4    > mk_lib_crypto_mode_cfb_128_serpent.h
    COMMAND ${M4_EXECUTABLE} -Q -I ${MK_CLIB_SOURCE_DIR} mk_lib_crypto_mode_cfb_8_aes_128.h.m4      > mk_lib_crypto_mode_cfb_8_aes_128.h
    COMMAND ${M4_EXECUTABLE} -Q -I ${MK_CLIB_SOURCE_DIR} mk_lib_crypto_mode_cfb_8_aes_192.h.m4      > mk_lib_crypto_mode_cfb_8_aes_192.h
    COMMAND ${M4_EXECUTABLE} -Q -I ${MK_CLIB_SOURCE_DIR} mk_lib_crypto_mode_cfb_8_aes_256.h.m4      > mk_lib_crypto_mode_cfb_8_aes_256.h
    COMMAND ${M4_EXECUTABLE} -Q -I ${MK_CLIB_SOURCE_DIR} mk_lib_crypto_mode_cfb_8_serpent.h.m4      > mk_lib_crypto_mode_cfb_8_serpent.h
    COMMAND ${M4_EXECUTABLE} -Q -I ${MK_CLIB_SOURCE_DIR} mk_lib_crypto_mode_ctr_be_aes_128.h.m4     > mk_lib_crypto_mode_ctr_be_aes_128.h
    COMMAND ${M4_EXECUTABLE} -Q -I ${MK_CLIB_SOURCE_DIR} mk_lib_crypto_mode_ctr_be_aes_192.h.m4     > mk_lib_crypto_mode_ctr_be_aes_192.h
    COMMAND ${M4_EXECUTABLE} -Q -I ${MK_CLIB_SOURCE_DIR} mk_lib_crypto_mode_ctr_be_aes_256.h.m4     > mk_lib_crypto_mode_ctr_be_aes_256.h
    COMMAND ${M4_EXECUTABLE} -Q -I ${MK_CLIB_SOURCE_DIR} mk_lib_crypto_mode_ctr_be_serpent.h.m4     > mk_lib_crypto_mode_ctr_be_serpent.h
    COMMAND ${M4_EXECUTABLE} -Q -I ${MK_CLIB_SOURCE_DIR} mk_lib_crypto_mode_ecb_aes_128.h.m4        > mk_lib_crypto_mode_ecb_aes_128.h
    COMMAND ${M4_EXECUTABLE} -Q -I ${MK_CLIB_SOURCE_DIR} mk_lib_crypto_mode_ecb_aes_192.h.m4        > mk_lib_crypto_mode_ecb_aes_192.h
    COMMAND ${M4_EXECUTABLE} -Q -I ${MK_CLIB_SOURCE_DIR} mk_lib_crypto_mode_ecb_aes_256.h.m4        > mk_lib_crypto_mode_ecb_aes_256.h
    COMMAND ${M4_EXECUTABLE} -Q -I ${MK_CLIB_SOURCE_DIR} mk_lib_crypto_mode_ecb_serpent.h.m4        > mk_lib_crypto_mode_ecb_serpent.h
    COMMAND ${M4_EXECUTABLE} -Q -I ${MK_CLIB_SOURCE_DIR} mk_lib_crypto_mode_ofb_aes_128.h.m4        > mk_lib_crypto_mode_ofb_aes_128.h
    COMMAND ${M4_EXECUTABLE} -Q -I ${MK_CLIB_SOURCE_DIR} mk_lib_crypto_mode_ofb_aes_192.h.m4        > mk_lib_crypto_mode_ofb_aes_192.h
    COMMAND ${M4_EXECUTABLE} -Q -I ${MK_CLIB_SOURCE_DIR} mk_lib_crypto_mode_ofb_aes_256.h.m4        > mk_lib_crypto_mode_ofb_aes_256.h
    COMMAND ${M4_EXECUTABLE} -Q -I ${MK_CLIB_SOURCE_DIR} mk_lib_crypto_mode_ofb_serpent.h.m4        > mk_lib_crypto_mode_ofb_serpent.h
    WORKING_DIRECTORY ${MK_CLIB_SOURCE_DIR}
)

file(GLOB MK_CLIB_SOURCE_FILES ${MK_CLIB_SOURCE_DIR}/*.c)
add_library(Deps_Mk_Clib_Crypto STATIC ${MK_CLIB_SOURCE_FILES})
target_include_directories(Deps_Mk_Clib_Crypto PUBLIC ${MK_CLIB_SOURCE_DIR})
set_property(TARGET Deps_Mk_Clib_Crypto PROPERTY CXX_STANDARD 23)
target_compile_definitions(Deps_Mk_Clib_Crypto PUBLIC mk_lang_jumbo_want=0)
target_compile_features(Deps_Mk_Clib_Crypto PUBLIC cxx_std_23)
add_dependencies(Deps_Mk_Clib_Crypto Deps_Mk_Clib_Crypto_M4PreBuild)
add_library(PWN::Deps::MkClib::Crypto ALIAS Deps_Mk_Clib_Crypto)
