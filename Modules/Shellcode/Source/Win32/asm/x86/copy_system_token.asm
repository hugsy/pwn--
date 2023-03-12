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
    ;;; TODO
    xor eax,eax
    ret
CopySystemToken_Win10 ENDP
CopySystemToken_Win10_end::

PUBLIC CopySystemTokenLength_Win10
CopySystemTokenLength_Win10 PROC
  mov eax, OFFSET CopySystemToken_Win10_end
  mov ecx, OFFSET CopySystemToken_Win10
  sub eax, ecx
  ret
CopySystemTokenLength_Win10 ENDP

_TEXT    ENDS
END
