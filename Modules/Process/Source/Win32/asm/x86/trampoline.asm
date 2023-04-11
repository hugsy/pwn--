EXTERN _HookCallbackLocation:NEAR

_DATA SEGMENT
_DATA ENDS

_TEXT    SEGMENT

_GoToTrampoline PROC PUBLIC
	mov eax, _HookCallbackLocation
	jmp eax
_GoToTrampoline ENDP
_GoToTrampoline_end::

_GoToTrampolineLength PROC PUBLIC
  mov eax, OFFSET _GoToTrampoline_end
  mov ecx, OFFSET _GoToTrampoline
  sub eax, ecx
  ret
_GoToTrampolineLength ENDP

_TEXT    ENDS
END
