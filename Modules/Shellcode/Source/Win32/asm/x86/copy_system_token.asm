_DATA SEGMENT
_DATA ENDS

_TEXT    SEGMENT

;;;
;;; Copy the system token to the current process
;;;

PUBLIC _CopySystemToken
_CopySystemToken PROC
    jmp _CopySystemToken_Win10
_CopySystemToken ENDP

PUBLIC _CopySystemTokenLength
_CopySystemTokenLength PROC
    jmp _CopySystemTokenLength_Win10
_CopySystemTokenLength ENDP


;;;
;;; OS specific shellcodes
;;;

PUBLIC _CopySystemToken_Win10
_CopySystemToken_Win10 PROC
    ;;; TODO
    xor eax,eax
    ret
_CopySystemToken_Win10 ENDP
_CopySystemToken_Win10_end::

PUBLIC _CopySystemTokenLength_Win10
_CopySystemTokenLength_Win10 PROC
  mov eax, OFFSET _CopySystemToken_Win10_end
  mov ecx, OFFSET _CopySystemToken_Win10
  sub eax, ecx
  ret
_CopySystemTokenLength_Win10 ENDP

_TEXT    ENDS
END
