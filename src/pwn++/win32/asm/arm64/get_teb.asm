_DATA SEGMENT
_DATA ENDS

_TEXT    SEGMENT

;;;
;;; Get the TEB (64b version)
;;;
PUBLIC GetTeb
GetTeb PROC
    mov  x0, x18
    ret
GetTeb ENDP
GetTeb_end::

PUBLIC GetTebLength
GetTebLength PROC
  mov x0, OFFSET GetTeb_end
  mov x8, OFFSET GetTeb
  sub x0, x0, x8
  ret
GetTebLength ENDP

;;;
;;; Get the PEB (64b version)
;;;
PUBLIC GetPeb
GetPeb PROC
    b  GetTeb
    ldr  x0, [x0,#0x60]
    ret
GetPeb ENDP
GetPeb_end::

PUBLIC GetPebLength
GetPebLength PROC
  mov x0, OFFSET GetPeb_end
  mov x8, OFFSET GetPeb
  sub x0, x0, x8
  ret
GetPebLength ENDP

_TEXT    ENDS
END
