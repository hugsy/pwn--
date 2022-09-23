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
  mov rcx, OFFSET GetTeb
  sub rax, rcx
  ret
GetTebLength ENDP

;;;
;;; Get the PEB (64b version)
;;;
PUBLIC GetPeb
GetPeb PROC
	push rbp
	mov rbp, rsp
	sub rsp, 8 * (4 + 2)
	mov rax, gs:[30h]
	mov rax, [rax + 60h]
	mov [rcx], rax
	xor rax, rax
	mov rsp, rbp
	pop rbp
	ret
GetPeb ENDP
GetPeb_end::

PUBLIC GetPebLength
GetPebLength PROC
  mov rax, OFFSET GetPeb_end
  mov rcx, OFFSET GetPeb
  sub rax, rcx
  ret
GetPebLength ENDP

_TEXT    ENDS
END
