include(FetchContent)

FetchContent_Declare(
    Deps_BinjaArm64
    GIT_REPOSITORY https://github.com/Vector35/arch-arm64.git
    GIT_TAG 948ebac497ac31cd014c8c09877f9d99d27647da
)
FetchContent_Populate(Deps_BinjaArm64)
FetchContent_GetProperties(Deps_BinjaArm64 SOURCE_DIR deps_binjaarm64_SOURCE_DIR)

message(STATUS "Using BinjaArm64 in '${deps_binjaarm64_SOURCE_DIR}'")

# set(BINJA_SOURCE_FILES
# ${deps_binjaarm64_SOURCE_DIR}/disassembler/decode.c
# ${deps_binjaarm64_SOURCE_DIR}/disassembler/format.c
# ${deps_binjaarm64_SOURCE_DIR}/disassembler/sysregs.c
# ${deps_binjaarm64_SOURCE_DIR}/disassembler/regs.c
# ${deps_binjaarm64_SOURCE_DIR}/disassembler/encodings_dec.c
# ${deps_binjaarm64_SOURCE_DIR}/disassembler/encodings_fmt.c
# ${deps_binjaarm64_SOURCE_DIR}/disassembler/operations.c
# ${deps_binjaarm64_SOURCE_DIR}/disassembler/pcode.c
# ${deps_binjaarm64_SOURCE_DIR}/disassembler/decode0.c
# ${deps_binjaarm64_SOURCE_DIR}/disassembler/decode1.c
# ${deps_binjaarm64_SOURCE_DIR}/disassembler/decode2.c
# ${deps_binjaarm64_SOURCE_DIR}/disassembler/decode_fields32.c
# ${deps_binjaarm64_SOURCE_DIR}/disassembler/decode_scratchpad.c
# )

# set(BINJA_HEADER_FILES
# ${deps_binjaarm64_SOURCE_DIR}/disassembler/arm64dis.h
# ${deps_binjaarm64_SOURCE_DIR}/disassembler/decode_fields32.h
# ${deps_binjaarm64_SOURCE_DIR}/disassembler/decode.h
# ${deps_binjaarm64_SOURCE_DIR}/disassembler/decode1.h
# ${deps_binjaarm64_SOURCE_DIR}/disassembler/decode2.h
# ${deps_binjaarm64_SOURCE_DIR}/disassembler/encodings_dec.h
# ${deps_binjaarm64_SOURCE_DIR}/disassembler/encodings_fmt.h
# ${deps_binjaarm64_SOURCE_DIR}/disassembler/feature_flags.h
# ${deps_binjaarm64_SOURCE_DIR}/disassembler/format.h
# ${deps_binjaarm64_SOURCE_DIR}/disassembler/operations.h
# ${deps_binjaarm64_SOURCE_DIR}/disassembler/pcode.h
# ${deps_binjaarm64_SOURCE_DIR}/disassembler/regs.h
# ${deps_binjaarm64_SOURCE_DIR}/disassembler/sysregs.h
# )

# add_library(Deps_BinjaArm64 STATIC ${BINJA_SOURCE_FILES} ${BINJA_HEADER_FILES})
add_library(Deps_BinjaArm64
    STATIC
    ${deps_binjaarm64_SOURCE_DIR}/disassembler/decode.c
    ${deps_binjaarm64_SOURCE_DIR}/disassembler/format.c
    ${deps_binjaarm64_SOURCE_DIR}/disassembler/sysregs.c
    ${deps_binjaarm64_SOURCE_DIR}/disassembler/regs.c
    ${deps_binjaarm64_SOURCE_DIR}/disassembler/encodings_dec.c
    ${deps_binjaarm64_SOURCE_DIR}/disassembler/encodings_fmt.c
    ${deps_binjaarm64_SOURCE_DIR}/disassembler/operations.c
    ${deps_binjaarm64_SOURCE_DIR}/disassembler/pcode.c
    ${deps_binjaarm64_SOURCE_DIR}/disassembler/decode0.c
    ${deps_binjaarm64_SOURCE_DIR}/disassembler/decode1.c
    ${deps_binjaarm64_SOURCE_DIR}/disassembler/decode2.c
    ${deps_binjaarm64_SOURCE_DIR}/disassembler/decode_fields32.c
    ${deps_binjaarm64_SOURCE_DIR}/disassembler/decode_scratchpad.c
)
target_include_directories(Deps_BinjaArm64 PUBLIC ${deps_binjaarm64_SOURCE_DIR}/disassembler)

set_target_properties(Deps_BinjaArm64 PROPERTIES
    C_STANDARD 99
    C_STANDARD_REQUIRED ON
    C_VISIBILITY_PRESET hidden
    VISIBILITY_INLINES_HIDDEN ON
    POSITION_INDEPENDENT_CODE ON)

if(WIN32)
    target_compile_definitions(Deps_BinjaArm64 PRIVATE _CRT_SECURE_NO_WARNINGS=1) # ignore unsafe `strcpy` warnings with cl
else()
    set_source_files_properties(arm64dis.c PROPERTIES COMPILE_FLAGS -fno-strict-aliasing)
endif()

install(TARGETS Deps_BinjaArm64 DESTINATION Library)
