_DATA SEGMENT
_DATA ENDS

_TEXT    SEGMENT

;;;
;;; Get the TEB (32b version)
;;;
PUBLIC GetTeb
GetTeb PROC
	push ebp
	mov ebp, esp
	sub esp, 4 * (4 + 2)
    mov eax, fs:[18h]
	mov [ecx], eax
	xor eax, eax
	mov esp, ebp
	pop ebp
	ret
GetTeb ENDP
GetTeb_end::

PUBLIC GetTebLength
GetTebLength PROC
  mov eax, OFFSET GetTeb_end
  mov ecx, OFFSET GetTeb
  sub eax, ecx
  ret
GetTebLength ENDP

;;;
;;; Get the PEB (32b version)
;;;
PUBLIC GetPeb
GetPeb PROC
	push ebp
	mov ebp, esp
	sub esp, 4 * (4 + 2)
    mov eax, fs:[18h]
	mov eax, [eax + 30h]
	mov [ecx], eax
	xor eax, eax
	mov esp, ebp
	pop ebp
	ret
GetPeb ENDP
GetPeb_end::

PUBLIC GetPebLength
GetPebLength PROC
  mov eax, OFFSET GetPeb_end
  mov ecx, OFFSET GetPeb
  sub eax, ecx
  ret
GetPebLength ENDP


_TEXT    ENDS
END
