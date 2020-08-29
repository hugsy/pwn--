#pragma once

#include "pwn.h"

IMPORT_EXTERNAL_FUNCTION(
    L"ntdll.dll", \
    NtCreateTransaction, \
    NTSTATUS, \
    PHANDLE            TransactionHandle, \
    ACCESS_MASK        DesiredAccess, \
    POBJECT_ATTRIBUTES ObjectAttributes, \
    LPGUID             Uow, \
    HANDLE             TmHandle, \
    ULONG              CreateOptions, \
    ULONG              IsolationLevel, \
    ULONG              IsolationFlags, \
    PLARGE_INTEGER     Timeout, \
    PUNICODE_STRING    Description \
);
