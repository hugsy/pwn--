_DATA SEGMENT
_DATA ENDS

_TEXT    SEGMENT

;;;
;;; Get the TEB (64b version)
;;;
PUBLIC GetTeb
GetTeb PROC
	push rbp
	mov rbp, rsp
	sub rsp, 8 * (4 + 2)
	mov rax, gs:[30h]
	mov [rcx], rax
	xor rax, rax
	mov rsp, rbp
	pop rbp
	ret
GetTeb ENDP
GetTeb_end::

PUBLIC GetTebLength
GetTebLength PROC
  mov rax, OFFSET GetTeb_end
  sub rax, OFFSET GetTeb
  ret
GetTebLength ENDP

_TEXT    ENDS
END