_DATA SEGMENT
_DATA ENDS

_TEXT    SEGMENT

;;;
;;; Get the TEB
;;;
PUBLIC GetTeb
GetTeb PROC
	push ebp
	mov ebp, esp
	sub esp, 4 * (4 + 2)
    mov eax, fs:[18h]
	mov esp, ebp
	pop ebp
	ret
GetTeb ENDP

_TEXT    ENDS
END