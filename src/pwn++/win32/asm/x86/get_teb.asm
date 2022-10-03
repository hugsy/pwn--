_DATA SEGMENT
_DATA ENDS

_TEXT    SEGMENT

;;;
;;; Get the TEB (32b version)
;;;
PUBLIC _GetTeb
_GetTeb PROC
	push ebp
	mov ebp, esp
	sub esp, 4 * (4 + 2)
    mov eax, fs:[24h]
	mov [ecx], eax
	xor eax, eax
	mov esp, ebp
	pop ebp
	ret
_GetTeb ENDP
_GetTeb_end::

PUBLIC _GetTebLength
_GetTebLength PROC
  mov eax, OFFSET _GetTeb_end
  mov ecx, OFFSET _GetTeb
  sub eax, ecx
  ret
_GetTebLength ENDP

;;;
;;; Get the PEB (32b version)
;;;
PUBLIC _GetPeb
_GetPeb PROC
	push ebp
	mov ebp, esp
	sub esp, 4 * (4 + 2)
    mov eax, fs:[30h]
	mov [ecx], eax
	xor eax, eax
	mov esp, ebp
	pop ebp
	ret
_GetPeb ENDP
_GetPeb_end::

PUBLIC _GetPebLength
_GetPebLength PROC
  mov eax, OFFSET _GetPeb_end
  mov ecx, OFFSET _GetPeb
  sub eax, ecx
  ret
_GetPebLength ENDP


_TEXT    ENDS
END
