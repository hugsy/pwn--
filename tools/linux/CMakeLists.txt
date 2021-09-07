#
# Build Linux test tools
#

# todo:
# - harden

if(NOT INCLUDE_DISASSEMBLER)
    add_compile_definitions(PWN_NO_DISASSEMBLER)
endif()

if(NOT INCLUDE_ASSEMBLER)
    add_compile_definitions(PWN_NO_ASSEMBLER)
endif()

add_subdirectory(ExploitTemplate)
