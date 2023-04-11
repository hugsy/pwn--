  GLOBAL GetPeb
  GLOBAL GetPebLength

CODE

GetTeb PROC
    mov  x0, x18
    ret
GetTeb ENDP
GetTeb_end::

GetTebLength PROC
  // adr x0, GetTeb_end TODO
  adr x8, GetTeb
  sub x0, x0, x8
  ret
GetTebLength ENDP

GetPeb PROC PUBLIC  EXPORT
  b  GetTeb
  ldr  x0, [x0, #0x60]
  ret
GetPeb ENDP
GetPeb_end::

GetPebLength PROC PUBLIC EXPORT
  // adr x0, GetPeb_end TODO
  adr x8, GetPeb
  sub x0, x0, x8
  ret
GetPebLength ENDP

ENDS

  END
