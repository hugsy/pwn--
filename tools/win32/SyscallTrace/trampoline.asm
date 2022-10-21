_DATA SEGMENT
    ; http://terminus.rewolf.pl/terminus/structures/ntdll/_KEXCEPTION_FRAME_x64.html
    KEXCEPTION_FRAME_LENGTH dq 138h
_DATA ENDS

EXTERN InstrumentationHook:NEAR

_TEXT    SEGMENT

GENERATE_EXCEPTION_FRAME MACRO
    sub rsp, KEXCEPTION_FRAME_LENGTH - 8
ENDM

RESTORE_EXCEPTION_STATE MACRO
    add rsp, KEXCEPTION_FRAME_LENGTH - 8
ENDM

PUBLIC Trampoline
Trampoline PROC
    mov r9, rax
    mov r8, rsp ; Previous SP
    mov rdx, r11 ; Previous RetCode
    mov rcx, r10 ; Previous PC (i.e. function address)
    call InstrumentationHook

    int 3
    jmp r9
Trampoline ENDP

_TEXT    ENDS
END
