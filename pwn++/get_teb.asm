_DATA SEGMENT
_DATA ENDS


_TEXT    SEGMENT

IFDEF RAX
;;; 
;;; Get the TEB (64b version)
;;; 

PUBLIC x64_get_teb
x64_get_teb PROC 
	push rbp
	mov rbp, rsp
	sub rsp, 8 * (4 + 2)
	mov rax, gs:[30h]
	mov rsp, rbp
	pop rbp
	ret
x64_get_teb ENDP


ELSE
;;; 
;;; Get the TEB (32b version)
;;; 

PUBLIC x86_get_teb
x86_get_teb PROC 
	push ebp
	mov ebp, esp
	sub esp, 4* (4 + 2)
    mov eax, fs:[18h]
	mov esp, ebp
	pop ebp
	ret
x86_get_teb ENDP


ENDIF


_TEXT    ENDS
END