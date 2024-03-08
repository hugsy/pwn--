include(FetchContent)

FetchContent_Declare(
    Deps_Mk_Clib
    GIT_REPOSITORY https://github.com/hugsy/mk_clib
    GIT_TAG 25435c8fd6d30330c43c589ea01859a6984d7f87
)
FetchContent_MakeAvailable(Deps_Mk_Clib)

message(STATUS "Using MkCLib in '${deps_mk_clib_SOURCE_DIR}'")

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

set(MK_CLIB_SOURCE_FILES
    ${MK_CLIB_SOURCE_DIR}/mk_lang_alignof_test.c
    ${MK_CLIB_SOURCE_DIR}/mk_lang_bi_info.c
    ${MK_CLIB_SOURCE_DIR}/mk_lang_bi_test.c
    ${MK_CLIB_SOURCE_DIR}/mk_lang_bui_example.c
    ${MK_CLIB_SOURCE_DIR}/mk_lang_check.c
    ${MK_CLIB_SOURCE_DIR}/mk_lang_clobber.c
    ${MK_CLIB_SOURCE_DIR}/mk_lang_cpuid.c
    ${MK_CLIB_SOURCE_DIR}/mk_lang_crash.c
    ${MK_CLIB_SOURCE_DIR}/mk_lang_exception_data.c
    ${MK_CLIB_SOURCE_DIR}/mk_lang_exception_out_of_memory.c
    ${MK_CLIB_SOURCE_DIR}/mk_lang_exception_test.c
    ${MK_CLIB_SOURCE_DIR}/mk_lang_exception.c
    ${MK_CLIB_SOURCE_DIR}/mk_lang_limits_test.c
    ${MK_CLIB_SOURCE_DIR}/mk_lang_num_longdivmod_fuzz_bui.c
    ${MK_CLIB_SOURCE_DIR}/mk_lang_num_longdivmod_fuzz_cui.c
    ${MK_CLIB_SOURCE_DIR}/mk_lang_sizeof_test.c
    ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_aes_fuzz.c
    ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_alg_aes_128.c
    ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_alg_aes_192.c
    ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_alg_aes_256.c
    ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_alg_aes_base.c
    ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_alg_serpent.c
    ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_app.c
    ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_gapp.c
    ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_hash_block_blake2b_256.c
    ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_hash_block_blake2b_384.c
    ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_hash_block_blake2b_512.c
    ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_hash_block_blake2b_base.c
    ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_hash_block_blake2s_128.c
    ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_hash_block_blake2s_160.c
    ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_hash_block_blake2s_224.c
    ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_hash_block_blake2s_256.c
    ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_hash_block_blake2s_base.c
    ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_hash_block_blake3.c
    ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_hash_block_md2.c
    ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_hash_block_md4.c
    ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_hash_block_md5.c
    ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_hash_block_sha0.c
    ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_hash_block_sha1.c
    ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_hash_block_sha1c.c
    ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_hash_block_sha2_224.c
    ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_hash_block_sha2_256.c
    ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_hash_block_sha2_384.c
    ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_hash_block_sha2_512_224.c
    ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_hash_block_sha2_512_256.c
    ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_hash_block_sha2_512.c
    ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_hash_block_sha2_base_32bit.c
    ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_hash_block_sha2_base_64bit.c
    ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_hash_block_sha2c_base_32bit.c
    ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_hash_block_sha3_224.c
    ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_hash_block_sha3_256.c
    ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_hash_block_sha3_384.c
    ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_hash_block_sha3_512.c
    ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_hash_block_sha3_base.c
    ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_hash_block_streebog_256.c
    ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_hash_block_streebog_512.c
    ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_hash_block_streebog_base.c
    ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_hash_block_tiger_128.c
    ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_hash_block_tiger_160.c
    ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_hash_block_tiger_192.c
    ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_hash_block_tiger_base.c
    ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_hash_block_tiger2_128.c
    ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_hash_block_tiger2_160.c
    ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_hash_block_tiger2_192.c
    ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_hash_block_whirlpool.c
    ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_hash_stream_blake2b_256.c
    ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_hash_stream_blake2b_384.c
    ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_hash_stream_blake2b_512.c
    ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_hash_stream_blake2b_base.c
    ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_hash_stream_blake2s_128.c
    ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_hash_stream_blake2s_160.c
    ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_hash_stream_blake2s_224.c
    ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_hash_stream_blake2s_256.c
    ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_hash_stream_blake2s_base.c
    ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_hash_stream_blake3.c
    ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_hash_stream_md2.c
    ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_hash_stream_md4.c
    ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_hash_stream_md5.c
    ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_hash_stream_sha0.c
    ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_hash_stream_sha1.c
    ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_hash_stream_sha1c.c
    ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_hash_stream_sha2_224.c
    ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_hash_stream_sha2_256.c
    ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_hash_stream_sha2_384.c
    ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_hash_stream_sha2_512_224.c
    ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_hash_stream_sha2_512_256.c
    ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_hash_stream_sha2_512.c
    ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_hash_stream_sha3_224.c
    ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_hash_stream_sha3_256.c
    ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_hash_stream_sha3_384.c
    ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_hash_stream_sha3_512.c
    ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_hash_stream_streebog_256.c
    ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_hash_stream_streebog_512.c
    ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_hash_stream_tiger_128.c
    ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_hash_stream_tiger_160.c
    ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_hash_stream_tiger_192.c
    ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_hash_stream_tiger2_128.c
    ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_hash_stream_tiger2_160.c
    ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_hash_stream_tiger2_192.c
    ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_hash_stream_whirlpool.c
    ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_kdf_pbkdf1_md2.c
    ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_kdf_pbkdf1_md5.c
    ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_kdf_pbkdf1_sha1.c
    ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_kdf_pbkdf1_sha1c.c
    ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_kdf_pbkdf1.c
    ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_kdf_pbkdf2_blake2b_256.c
    ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_kdf_pbkdf2_blake2b_384.c
    ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_kdf_pbkdf2_blake2b_512.c
    ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_kdf_pbkdf2_blake2s_128.c
    ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_kdf_pbkdf2_blake2s_160.c
    ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_kdf_pbkdf2_blake2s_224.c
    ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_kdf_pbkdf2_blake2s_256.c
    ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_kdf_pbkdf2_blake3.c
    ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_kdf_pbkdf2_md2.c
    ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_kdf_pbkdf2_md4.c
    ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_kdf_pbkdf2_md5.c
    ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_kdf_pbkdf2_sha0.c
    ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_kdf_pbkdf2_sha1.c
    ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_kdf_pbkdf2_sha1c.c
    ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_kdf_pbkdf2_sha2_224.c
    ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_kdf_pbkdf2_sha2_256.c
    ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_kdf_pbkdf2_sha2_384.c
    ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_kdf_pbkdf2_sha2_512_224.c
    ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_kdf_pbkdf2_sha2_512_256.c
    ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_kdf_pbkdf2_sha2_512.c
    ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_kdf_pbkdf2_sha3_224.c
    ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_kdf_pbkdf2_sha3_256.c
    ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_kdf_pbkdf2_sha3_384.c
    ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_kdf_pbkdf2_sha3_512.c
    ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_kdf_pbkdf2_streebog_256.c
    ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_kdf_pbkdf2_streebog_512.c
    ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_kdf_pbkdf2_tiger_128.c
    ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_kdf_pbkdf2_tiger_160.c
    ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_kdf_pbkdf2_tiger_192.c
    ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_kdf_pbkdf2_tiger2_128.c
    ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_kdf_pbkdf2_tiger2_160.c
    ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_kdf_pbkdf2_tiger2_192.c
    ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_kdf_pbkdf2_whirlpool.c
    ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_mac_hmac_blake2b_256.c
    ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_mac_hmac_blake2b_384.c
    ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_mac_hmac_blake2b_512.c
    ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_mac_hmac_blake2s_128.c
    ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_mac_hmac_blake2s_160.c
    ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_mac_hmac_blake2s_224.c
    ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_mac_hmac_blake2s_256.c
    ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_mac_hmac_blake3.c
    ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_mac_hmac_md2.c
    ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_mac_hmac_md4.c
    ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_mac_hmac_md5.c
    ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_mac_hmac_sha0.c
    ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_mac_hmac_sha1.c
    ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_mac_hmac_sha1c.c
    ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_mac_hmac_sha2_224.c
    ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_mac_hmac_sha2_256.c
    ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_mac_hmac_sha2_384.c
    ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_mac_hmac_sha2_512_224.c
    ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_mac_hmac_sha2_512_256.c
    ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_mac_hmac_sha2_512.c
    ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_mac_hmac_sha3_224.c
    ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_mac_hmac_sha3_256.c
    ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_mac_hmac_sha3_384.c
    ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_mac_hmac_sha3_512.c
    ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_mac_hmac_streebog_256.c
    ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_mac_hmac_streebog_512.c
    ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_mac_hmac_tiger_128.c
    ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_mac_hmac_tiger_160.c
    ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_mac_hmac_tiger_192.c
    ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_mac_hmac_tiger2_128.c
    ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_mac_hmac_tiger2_160.c
    ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_mac_hmac_tiger2_192.c
    ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_mac_hmac_whirlpool.c
    ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_mode_cbc_aes_128.c
    ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_mode_cbc_aes_192.c
    ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_mode_cbc_aes_256.c
    ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_mode_cbc_serpent.c
    ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_mode_cfb_128_aes_128.c
    ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_mode_cfb_128_aes_192.c
    ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_mode_cfb_128_aes_256.c
    ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_mode_cfb_128_serpent.c
    ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_mode_cfb_8_aes_128.c
    ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_mode_cfb_8_aes_192.c
    ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_mode_cfb_8_aes_256.c
    ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_mode_cfb_8_serpent.c
    ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_mode_ctr_be_aes_128.c
    ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_mode_ctr_be_aes_192.c
    ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_mode_ctr_be_aes_256.c
    ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_mode_ctr_be_serpent.c
    ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_mode_ecb_aes_128.c
    ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_mode_ecb_aes_192.c
    ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_mode_ecb_aes_256.c
    ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_mode_ecb_serpent.c
    ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_mode_ofb_aes_128.c
    ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_mode_ofb_aes_192.c
    ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_mode_ofb_aes_256.c
    ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_mode_ofb_serpent.c
    ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_padding_iso9797pm2.c
    ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_padding_pkcs7.c
    ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_serpent_fuzz.c
    ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_xof_block_shake_128.c
    ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_xof_block_shake_256.c
    ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_xof_stream_shake_128.c
    ${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_xof_stream_shake_256.c
    ${MK_CLIB_SOURCE_DIR}/mk_lib_flt_analyzer_double.c
    ${MK_CLIB_SOURCE_DIR}/mk_lib_flt_analyzer_float.c
    ${MK_CLIB_SOURCE_DIR}/mk_lib_fmt.c
    ${MK_CLIB_SOURCE_DIR}/mk_sl_buffer_lang.c
    ${MK_CLIB_SOURCE_DIR}/mk_sl_cui_example.c
    ${MK_CLIB_SOURCE_DIR}/mk_sl_flt_fuzz.c
    ${MK_CLIB_SOURCE_DIR}/mk_sl_flt.c
    ${MK_CLIB_SOURCE_DIR}/mk_sl_mallocator_lang.c
    ${MK_CLIB_SOURCE_DIR}/mk_sl_sort_merge_fuzz.c
    ${MK_CLIB_SOURCE_DIR}/mk_sl_uint.c
    ${MK_CLIB_SOURCE_DIR}/mk_sl_uint1024.c
    ${MK_CLIB_SOURCE_DIR}/mk_sl_uint128.c
    ${MK_CLIB_SOURCE_DIR}/mk_sl_uint16.c
    ${MK_CLIB_SOURCE_DIR}/mk_sl_uint256.c
    ${MK_CLIB_SOURCE_DIR}/mk_sl_uint32.c
    ${MK_CLIB_SOURCE_DIR}/mk_sl_uint512.c
    ${MK_CLIB_SOURCE_DIR}/mk_sl_uint64.c
    ${MK_CLIB_SOURCE_DIR}/mk_sl_uint8.c
)

if(WIN32)
    set(MK_CLIB_SOURCE_FILES
        ${MK_CLIB_SOURCE_FILES}
        ${MK_CLIB_SOURCE_DIR}/mk_win_advapi.c
        ${MK_CLIB_SOURCE_DIR}/mk_win_base.c
        ${MK_CLIB_SOURCE_DIR}/mk_win_bcrypt.c
    )
endif(WIN32)

add_library(Deps_Mk_Clib_Crypto STATIC ${MK_CLIB_SOURCE_FILES})
target_include_directories(Deps_Mk_Clib_Crypto PUBLIC ${MK_CLIB_SOURCE_DIR})
set_property(TARGET Deps_Mk_Clib_Crypto PROPERTY CXX_STANDARD 23)
target_compile_definitions(
    Deps_Mk_Clib_Crypto
    PUBLIC mk_lang_jumbo_want=0
    PRIVATE $<$<NOT:$<CONFIG:Debug>>:NDEBUG>
)
target_compile_features(Deps_Mk_Clib_Crypto PUBLIC cxx_std_23)
add_dependencies(Deps_Mk_Clib_Crypto Deps_Mk_Clib_Crypto_M4PreBuild)
add_library(PWN::Deps::MkClib::Crypto ALIAS Deps_Mk_Clib_Crypto)

#
# Architecture specific
#
target_sources(
    Deps_Mk_Clib_Crypto
    PRIVATE
    $<$<STREQUAL:${CMAKE_GENERATOR_PLATFORM},win32>:${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_hash_block_sha1x86.c>
    $<$<STREQUAL:${CMAKE_GENERATOR_PLATFORM},win32>:${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_hash_block_sha2x86_base_32bit.c>
    $<$<STREQUAL:${CMAKE_GENERATOR_PLATFORM},win32>:${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_hash_stream_sha1x86.c>
    $<$<STREQUAL:${CMAKE_GENERATOR_PLATFORM},win32>:${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_kdf_pbkdf1_sha1x86.c>
    $<$<STREQUAL:${CMAKE_GENERATOR_PLATFORM},win32>:${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_kdf_pbkdf2_sha1x86.c>
    $<$<STREQUAL:${CMAKE_GENERATOR_PLATFORM},win32>:${MK_CLIB_SOURCE_DIR}/mk_lib_crypto_mac_hmac_sha1x86.c>
)
