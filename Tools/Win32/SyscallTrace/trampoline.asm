_DATA SEGMENT
    ; http://terminus.rewolf.pl/terminus/structures/ntdll/_KEXCEPTION_FRAME_x64.html
    KEXCEPTION_FRAME_LENGTH dq 138h
_DATA ENDS

EXTERN InstrumentationHook:NEAR
EXTERNDEF __imp_RtlCaptureContext:QWORD

_TEXT    SEGMENT

GENERATE_EXCEPTION_FRAME MACRO
    sub rsp, KEXCEPTION_FRAME_LENGTH - 8
ENDM

RESTORE_EXCEPTION_STATE MACRO
    add rsp, KEXCEPTION_FRAME_LENGTH - 8
ENDM

;;;
;;; https://gist.github.com/esoterix/df38008568c50d4f83123e3a90b62ebb
;;;
PUBLIC Trampoline
Trampoline PROC
	mov     gs:[2e0h], rsp            ; Win10 TEB InstrumentationCallbackPreviousSp
	mov     gs:[2d8h], r10            ; Win10 TEB InstrumentationCallbackPreviousPc
	mov     r10, rcx                  ; Save original RCX
	sub     rsp, 4d0h                 ; Alloc stack space for CONTEXT structure
	and     rsp, -10h                 ; RSP must be 16 byte aligned before calls
	mov     rcx, rsp
	call    __imp_RtlCaptureContext   ; Save the current register state. RtlCaptureContext does not require shadow space
	sub     rsp, 20h                  ; Shadow space
	call    InstrumentationHook
	int     3
Trampoline ENDP

_TEXT    ENDS
END
