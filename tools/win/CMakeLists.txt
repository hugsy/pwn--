#
# Build Windows test tools
#

# todo:
# - harden with: add_compile_options(/W3 /WX /Wall /Wall /sdl /guard:cf /guard:ehcont /CETCOMPAT)

if(NOT INCLUDE_DISASSEMBLER)
    add_compile_definitions(PWN_NO_DISASSEMBLER)
endif()

if(NOT INCLUDE_ASSEMBLER)
    add_compile_definitions(PWN_NO_ASSEMBLER)
endif()

add_compile_definitions(_UNICODE)
add_compile_definitions(UNICODE)

add_subdirectory(AppContainMe)
add_subdirectory(HexdumpFile)
add_subdirectory(ProcessReparent)
