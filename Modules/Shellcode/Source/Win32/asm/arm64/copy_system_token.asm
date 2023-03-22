_DATA SEGMENT
_DATA ENDS

_TEXT    SEGMENT

;;;
;;; Copy the system token to the current process
;;;

PUBLIC CopySystemToken
CopySystemToken PROC
    ret
CopySystemToken ENDP

PUBLIC CopySystemTokenLength
CopySystemTokenLength PROC
    ret
CopySystemTokenLength ENDP


;;;
;;; OS specific shellcodes
;;;

PUBLIC CopySystemToken_Win10
CopySystemToken_Win10 PROC
    ret
CopySystemToken_Win10 ENDP
CopySystemToken_Win10_end::

PUBLIC CopySystemTokenLength_Win10
CopySystemTokenLength_Win10 PROC
    ret
CopySystemTokenLength_Win10 ENDP

_TEXT    ENDS
END
