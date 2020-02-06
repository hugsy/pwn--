_DATA SEGMENT
_DATA ENDS


_TEXT    SEGMENT

PUBLIC __asm__get_teb_x64
 ; no args
 __asm__get_teb_x64 PROC 
;;; prologue
push rbp
mov rbp, rsp
sub rsp, 8 * (4 + 2)

mov rax, gs:[30h]

;;; epilogue
mov rsp, rbp
pop rbp
ret

__asm__get_teb_x64 ENDP

_TEXT    ENDS

END