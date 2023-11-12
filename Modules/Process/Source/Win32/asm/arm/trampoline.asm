  GLOBAL GoToTrampoline
  GLOBAL GoToTrampolineLength

CODE

GoToTrampoline PROC PUBLIC EXPORT
  ;;; TODO
  bx lr
GoToTrampoline ENDP
GoToTrampoline_end::

GoToTrampolineLength PROC PUBLIC EXPORT
  ;;; TODO
  bx lr
GoToTrampolineLength ENDP

ENDS

  END
