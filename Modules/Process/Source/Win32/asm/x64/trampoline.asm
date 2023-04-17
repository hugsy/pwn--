EXTERN HookCallbackLocation:NEAR

_DATA SEGMENT
_DATA ENDS

_TEXT    SEGMENT
PUBLIC GoToTrampoline
GoToTrampoline PROC
	mov rax, HookCallbackLocation
	jmp rax
GoToTrampoline ENDP
GoToTrampoline_end::

PUBLIC GoToTrampolineLength
GoToTrampolineLength PROC
  mov rax, OFFSET GoToTrampoline_end
  mov rcx, OFFSET GoToTrampoline
  sub rax, rcx
  ret
GoToTrampolineLength ENDP

_TEXT    ENDS
END
