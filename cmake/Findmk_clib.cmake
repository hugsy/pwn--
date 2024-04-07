include(FetchContent)

FetchContent_Declare(
    deps_mk_clib
    GIT_REPOSITORY https://github.com/MarekKnapek/mk_clib.git
    GIT_TAG 14317ca3a4bad459c7b102a7d2af066e467130f9
)
FetchContent_MakeAvailable(deps_mk_clib)

message(STATUS "Using mk_clib in '${deps_mk_clib_SOURCE_DIR}'")

set(MK_CLIB_SOURCE_DIR ${deps_mk_clib_SOURCE_DIR}/mk_clib/src)

find_program(
    M4_EXECUTABLE m4
    HINTS
        "C:/Program Files (x86)/GnuWin32/bin"
        "/usr/bin"
)
if(NOT M4_EXECUTABLE)
    message(FATAL_ERROR "m4 macro processor not found")
endif()

set(MK_CLIB_SOURCE_M4_H
    ${MK_CLIB_SOURCE_DIR}/mk_lang_bui_inl_defd.h
    ${MK_CLIB_SOURCE_DIR}/mk_lang_bui_inl_defu.h
    ${MK_CLIB_SOURCE_DIR}/mk_lang_bui_inl_filec.h
    ${MK_CLIB_SOURCE_DIR}/mk_lang_bui_inl_fileh.h
    ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_alg_aes_128.h
    ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_alg_aes_192.h
    ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_alg_aes_256.h
    ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_mode_cbc_aes_128.h
    ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_mode_cbc_aes_192.h
    ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_mode_cbc_aes_256.h
    ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_mode_cbc_des.h
    ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_mode_cbc_serpent.h
    ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_mode_cbc_tdes2.h
    ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_mode_cbc_tdes3.h
    ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_mode_cfb_128_aes_128.h
    ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_mode_cfb_128_aes_192.h
    ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_mode_cfb_128_aes_256.h
    ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_mode_cfb_128_serpent.h
    ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_mode_cfb_64_des.h
    ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_mode_cfb_64_tdes2.h
    ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_mode_cfb_64_tdes3.h
    ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_mode_cfb_8_aes_128.h
    ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_mode_cfb_8_aes_192.h
    ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_mode_cfb_8_aes_256.h
    ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_mode_cfb_8_des.h
    ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_mode_cfb_8_serpent.h
    ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_mode_cfb_8_tdes2.h
    ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_mode_cfb_8_tdes3.h
    ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_mode_ctr_be_aes_128.h
    ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_mode_ctr_be_aes_192.h
    ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_mode_ctr_be_aes_256.h
    ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_mode_ctr_be_des.h
    ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_mode_ctr_be_serpent.h
    ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_mode_ctr_be_tdes2.h
    ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_mode_ctr_be_tdes3.h
    ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_mode_ecb_aes_128.h
    ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_mode_ecb_aes_192.h
    ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_mode_ecb_aes_256.h
    ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_mode_ecb_des.h
    ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_mode_ecb_serpent.h
    ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_mode_ecb_tdes2.h
    ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_mode_ecb_tdes3.h
    ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_mode_ofb_aes_128.h
    ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_mode_ofb_aes_192.h
    ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_mode_ofb_aes_256.h
    ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_mode_ofb_des.h
    ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_mode_ofb_serpent.h
    ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_mode_ofb_tdes2.h
    ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_mode_ofb_tdes3.h
    ${MK_CLIB_SOURCE_DIR}/mk_sl_cui_inl_defd.h
    ${MK_CLIB_SOURCE_DIR}/mk_sl_cui_inl_defu.h
    ${MK_CLIB_SOURCE_DIR}/mk_sl_cui_inl_filec.h
    ${MK_CLIB_SOURCE_DIR}/mk_sl_cui_inl_fileh.h
)

add_custom_command(
    OUTPUT ${MK_CLIB_SOURCE_M4_H}
    WORKING_DIRECTORY ${MK_CLIB_SOURCE_DIR}
    COMMAND ${M4_EXECUTABLE} -Q -I ${MK_CLIB_SOURCE_DIR} ${MK_CLIB_SOURCE_DIR}/mk_lang_bui_inl_defd.h.m4               > ${MK_CLIB_SOURCE_DIR}/mk_lang_bui_inl_defd.h
    COMMAND ${M4_EXECUTABLE} -Q -I ${MK_CLIB_SOURCE_DIR} ${MK_CLIB_SOURCE_DIR}/mk_lang_bui_inl_defu.h.m4               > ${MK_CLIB_SOURCE_DIR}/mk_lang_bui_inl_defu.h
    COMMAND ${M4_EXECUTABLE} -Q -I ${MK_CLIB_SOURCE_DIR} ${MK_CLIB_SOURCE_DIR}/mk_lang_bui_inl_filec.h.m4              > ${MK_CLIB_SOURCE_DIR}/mk_lang_bui_inl_filec.h
    COMMAND ${M4_EXECUTABLE} -Q -I ${MK_CLIB_SOURCE_DIR} ${MK_CLIB_SOURCE_DIR}/mk_lang_bui_inl_fileh.h.m4              > ${MK_CLIB_SOURCE_DIR}/mk_lang_bui_inl_fileh.h
    COMMAND ${M4_EXECUTABLE} -Q -I ${MK_CLIB_SOURCE_DIR} ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_alg_aes_128.h.m4          > ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_alg_aes_128.h
    COMMAND ${M4_EXECUTABLE} -Q -I ${MK_CLIB_SOURCE_DIR} ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_alg_aes_192.h.m4          > ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_alg_aes_192.h
    COMMAND ${M4_EXECUTABLE} -Q -I ${MK_CLIB_SOURCE_DIR} ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_alg_aes_256.h.m4          > ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_alg_aes_256.h
    COMMAND ${M4_EXECUTABLE} -Q -I ${MK_CLIB_SOURCE_DIR} ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_mode_cbc_aes_128.h.m4     > ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_mode_cbc_aes_128.h
    COMMAND ${M4_EXECUTABLE} -Q -I ${MK_CLIB_SOURCE_DIR} ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_mode_cbc_aes_192.h.m4     > ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_mode_cbc_aes_192.h
    COMMAND ${M4_EXECUTABLE} -Q -I ${MK_CLIB_SOURCE_DIR} ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_mode_cbc_aes_256.h.m4     > ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_mode_cbc_aes_256.h
    COMMAND ${M4_EXECUTABLE} -Q -I ${MK_CLIB_SOURCE_DIR} ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_mode_cbc_des.h.m4         > ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_mode_cbc_des.h
    COMMAND ${M4_EXECUTABLE} -Q -I ${MK_CLIB_SOURCE_DIR} ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_mode_cbc_serpent.h.m4     > ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_mode_cbc_serpent.h
    COMMAND ${M4_EXECUTABLE} -Q -I ${MK_CLIB_SOURCE_DIR} ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_mode_cbc_tdes2.h.m4       > ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_mode_cbc_tdes2.h
    COMMAND ${M4_EXECUTABLE} -Q -I ${MK_CLIB_SOURCE_DIR} ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_mode_cbc_tdes3.h.m4       > ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_mode_cbc_tdes3.h
    COMMAND ${M4_EXECUTABLE} -Q -I ${MK_CLIB_SOURCE_DIR} ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_mode_cfb_128_aes_128.h.m4 > ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_mode_cfb_128_aes_128.h
    COMMAND ${M4_EXECUTABLE} -Q -I ${MK_CLIB_SOURCE_DIR} ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_mode_cfb_128_aes_192.h.m4 > ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_mode_cfb_128_aes_192.h
    COMMAND ${M4_EXECUTABLE} -Q -I ${MK_CLIB_SOURCE_DIR} ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_mode_cfb_128_aes_256.h.m4 > ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_mode_cfb_128_aes_256.h
    COMMAND ${M4_EXECUTABLE} -Q -I ${MK_CLIB_SOURCE_DIR} ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_mode_cfb_128_serpent.h.m4 > ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_mode_cfb_128_serpent.h
    COMMAND ${M4_EXECUTABLE} -Q -I ${MK_CLIB_SOURCE_DIR} ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_mode_cfb_64_des.h.m4      > ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_mode_cfb_64_des.h
    COMMAND ${M4_EXECUTABLE} -Q -I ${MK_CLIB_SOURCE_DIR} ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_mode_cfb_64_tdes2.h.m4    > ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_mode_cfb_64_tdes2.h
    COMMAND ${M4_EXECUTABLE} -Q -I ${MK_CLIB_SOURCE_DIR} ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_mode_cfb_64_tdes3.h.m4    > ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_mode_cfb_64_tdes3.h
    COMMAND ${M4_EXECUTABLE} -Q -I ${MK_CLIB_SOURCE_DIR} ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_mode_cfb_8_aes_128.h.m4   > ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_mode_cfb_8_aes_128.h
    COMMAND ${M4_EXECUTABLE} -Q -I ${MK_CLIB_SOURCE_DIR} ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_mode_cfb_8_aes_192.h.m4   > ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_mode_cfb_8_aes_192.h
    COMMAND ${M4_EXECUTABLE} -Q -I ${MK_CLIB_SOURCE_DIR} ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_mode_cfb_8_aes_256.h.m4   > ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_mode_cfb_8_aes_256.h
    COMMAND ${M4_EXECUTABLE} -Q -I ${MK_CLIB_SOURCE_DIR} ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_mode_cfb_8_des.h.m4       > ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_mode_cfb_8_des.h
    COMMAND ${M4_EXECUTABLE} -Q -I ${MK_CLIB_SOURCE_DIR} ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_mode_cfb_8_serpent.h.m4   > ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_mode_cfb_8_serpent.h
    COMMAND ${M4_EXECUTABLE} -Q -I ${MK_CLIB_SOURCE_DIR} ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_mode_cfb_8_tdes2.h.m4     > ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_mode_cfb_8_tdes2.h
    COMMAND ${M4_EXECUTABLE} -Q -I ${MK_CLIB_SOURCE_DIR} ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_mode_cfb_8_tdes3.h.m4     > ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_mode_cfb_8_tdes3.h
    COMMAND ${M4_EXECUTABLE} -Q -I ${MK_CLIB_SOURCE_DIR} ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_mode_ctr_be_aes_128.h.m4  > ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_mode_ctr_be_aes_128.h
    COMMAND ${M4_EXECUTABLE} -Q -I ${MK_CLIB_SOURCE_DIR} ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_mode_ctr_be_aes_192.h.m4  > ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_mode_ctr_be_aes_192.h
    COMMAND ${M4_EXECUTABLE} -Q -I ${MK_CLIB_SOURCE_DIR} ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_mode_ctr_be_aes_256.h.m4  > ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_mode_ctr_be_aes_256.h
    COMMAND ${M4_EXECUTABLE} -Q -I ${MK_CLIB_SOURCE_DIR} ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_mode_ctr_be_des.h.m4      > ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_mode_ctr_be_des.h
    COMMAND ${M4_EXECUTABLE} -Q -I ${MK_CLIB_SOURCE_DIR} ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_mode_ctr_be_serpent.h.m4  > ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_mode_ctr_be_serpent.h
    COMMAND ${M4_EXECUTABLE} -Q -I ${MK_CLIB_SOURCE_DIR} ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_mode_ctr_be_tdes2.h.m4    > ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_mode_ctr_be_tdes2.h
    COMMAND ${M4_EXECUTABLE} -Q -I ${MK_CLIB_SOURCE_DIR} ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_mode_ctr_be_tdes3.h.m4    > ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_mode_ctr_be_tdes3.h
    COMMAND ${M4_EXECUTABLE} -Q -I ${MK_CLIB_SOURCE_DIR} ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_mode_ecb_aes_128.h.m4     > ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_mode_ecb_aes_128.h
    COMMAND ${M4_EXECUTABLE} -Q -I ${MK_CLIB_SOURCE_DIR} ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_mode_ecb_aes_192.h.m4     > ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_mode_ecb_aes_192.h
    COMMAND ${M4_EXECUTABLE} -Q -I ${MK_CLIB_SOURCE_DIR} ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_mode_ecb_aes_256.h.m4     > ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_mode_ecb_aes_256.h
    COMMAND ${M4_EXECUTABLE} -Q -I ${MK_CLIB_SOURCE_DIR} ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_mode_ecb_des.h.m4         > ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_mode_ecb_des.h
    COMMAND ${M4_EXECUTABLE} -Q -I ${MK_CLIB_SOURCE_DIR} ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_mode_ecb_serpent.h.m4     > ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_mode_ecb_serpent.h
    COMMAND ${M4_EXECUTABLE} -Q -I ${MK_CLIB_SOURCE_DIR} ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_mode_ecb_tdes2.h.m4       > ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_mode_ecb_tdes2.h
    COMMAND ${M4_EXECUTABLE} -Q -I ${MK_CLIB_SOURCE_DIR} ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_mode_ecb_tdes3.h.m4       > ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_mode_ecb_tdes3.h
    COMMAND ${M4_EXECUTABLE} -Q -I ${MK_CLIB_SOURCE_DIR} ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_mode_ofb_aes_128.h.m4     > ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_mode_ofb_aes_128.h
    COMMAND ${M4_EXECUTABLE} -Q -I ${MK_CLIB_SOURCE_DIR} ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_mode_ofb_aes_192.h.m4     > ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_mode_ofb_aes_192.h
    COMMAND ${M4_EXECUTABLE} -Q -I ${MK_CLIB_SOURCE_DIR} ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_mode_ofb_aes_256.h.m4     > ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_mode_ofb_aes_256.h
    COMMAND ${M4_EXECUTABLE} -Q -I ${MK_CLIB_SOURCE_DIR} ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_mode_ofb_des.h.m4         > ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_mode_ofb_des.h
    COMMAND ${M4_EXECUTABLE} -Q -I ${MK_CLIB_SOURCE_DIR} ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_mode_ofb_serpent.h.m4     > ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_mode_ofb_serpent.h
    COMMAND ${M4_EXECUTABLE} -Q -I ${MK_CLIB_SOURCE_DIR} ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_mode_ofb_tdes2.h.m4       > ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_mode_ofb_tdes2.h
    COMMAND ${M4_EXECUTABLE} -Q -I ${MK_CLIB_SOURCE_DIR} ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_mode_ofb_tdes3.h.m4       > ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_mode_ofb_tdes3.h
    COMMAND ${M4_EXECUTABLE} -Q -I ${MK_CLIB_SOURCE_DIR} ${MK_CLIB_SOURCE_DIR}/mk_sl_cui_inl_defd.h.m4                 > ${MK_CLIB_SOURCE_DIR}/mk_sl_cui_inl_defd.h
    COMMAND ${M4_EXECUTABLE} -Q -I ${MK_CLIB_SOURCE_DIR} ${MK_CLIB_SOURCE_DIR}/mk_sl_cui_inl_defu.h.m4                 > ${MK_CLIB_SOURCE_DIR}/mk_sl_cui_inl_defu.h
    COMMAND ${M4_EXECUTABLE} -Q -I ${MK_CLIB_SOURCE_DIR} ${MK_CLIB_SOURCE_DIR}/mk_sl_cui_inl_filec.h.m4                > ${MK_CLIB_SOURCE_DIR}/mk_sl_cui_inl_filec.h
    COMMAND ${M4_EXECUTABLE} -Q -I ${MK_CLIB_SOURCE_DIR} ${MK_CLIB_SOURCE_DIR}/mk_sl_cui_inl_fileh.h.m4                > ${MK_CLIB_SOURCE_DIR}/mk_sl_cui_inl_fileh.h
)

add_library(deps_mk_clib_crypto INTERFACE ${MK_CLIB_SOURCE_M4_H})
target_include_directories(deps_mk_clib_crypto INTERFACE ${MK_CLIB_SOURCE_DIR})
add_library(PWN::Deps::mk_clib::Crypto ALIAS deps_mk_clib_crypto)
