#pragma once

#include "Win32/Resolver.hpp"

namespace pwn::Resolver::ntdll
{

ExternalImport(
    "ntdll.dll",
    NtCreateFile,
    NTSTATUS,
    PHANDLE FileHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PIO_STATUS_BLOCK IoStatusBlock,
    PLARGE_INTEGER AllocationSize,
    ULONG FileAttributes,
    ULONG ShareAccess,
    ULONG CreateDisposition,
    ULONG CreateOptions,
    PVOID EaBuffer,
    ULONG EaLength);

ExternalImport(
    "ntdll.dll",
    RtlImageDirectoryEntryToData,
    PVOID,
    PVOID Base,
    BOOLEAN MappedAsImage,
    USHORT DirectoryEntry,
    PULONG Size);

ExternalImport(
    "ntdll.dll",
    NtCreateSymbolicLinkObject,
    NTSTATUS,
    PHANDLE LinkHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PUNICODE_STRING TargetName);

ExternalImport(
    "ntdll.dll",
    NtOpenSymbolicLinkObject,
    NTSTATUS,
    PHANDLE LinkHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes);

ExternalImport(
    "ntdll.dll",
    NtWow64ReadVirtualMemory64,
    NTSTATUS,
    HANDLE ProcessHandle,
    PVOID64 BaseAddress,
    PVOID Buffer,
    ULONG64 Size,
    PULONG64 NumberOfBytesRead);

ExternalImport(
    "ntdll.dll",
    NtWow64WriteVirtualMemory64,
    NTSTATUS,
    HANDLE ProcessHandle,
    PVOID64 BaseAddress,
    PVOID Buffer,
    ULONG64 Size,
    PULONG64 NumberOfBytesWritten);

ExternalImport(
    "ntdll.dll",
    NtWow64QueryInformationProcess64,
    NTSTATUS,
    HANDLE ProcessHandle,
    PROCESSINFOCLASS ProcessInformationClass,
    PVOID ProcessInformation,
    ULONG ProcessInformationLength,
    PULONG ReturnLength);

ExternalImport(
    "ntdll.dll",
    NtSetInformationProcess,
    NTSTATUS,
    HANDLE ProcessHandle,
    int ProcessInformationClass,
    PVOID ProcessInformation,
    ULONG ProcessInformationLength);

ExternalImport(
    "ntdll.dll",
    NtQuerySystemEnvironmentValueEx,
    NTSTATUS,
    PUNICODE_STRING VariableName,
    LPGUID VendorGuid,
    PVOID Value,
    PULONG ValueLength,
    PULONG Attributes);

ExternalImport(
    "ntdll.dll",
    NtSetSystemEnvironmentValueEx,
    NTSTATUS,
    PUNICODE_STRING VariableName,
    LPGUID VendorGuid,
    PVOID Value,
    ULONG ValueLength,
    ULONG Attributes);

ExternalImport(
    "ntdll.dll",
    NtQueryInformationProcess,
    NTSTATUS,
    HANDLE ProcessHandle,
    PROCESSINFOCLASS ProcessInformationClass,
    PVOID ProcessInformation,
    ULONG ProcessInformationLength,
    PULONG ReturnLength);

ExternalImport(
    "ntdll.dll",
    NtCreateProcess,
    NTSTATUS,
    _Out_ PHANDLE ProcessHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_ HANDLE ParentProcess,
    _In_ BOOLEAN InheritObjectTable,
    _In_opt_ HANDLE SectionHandle,
    _In_opt_ HANDLE DebugPort,
    _In_opt_ HANDLE ExceptionPort);

ExternalImport(
    "ntdll.dll",
    NtCreateProcessEx,
    NTSTATUS,
    _Out_ PHANDLE ProcessHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_ HANDLE ParentProcess,
    _In_ ULONG Flags,
    _In_opt_ HANDLE SectionHandle,
    _In_opt_ HANDLE DebugPort,
    _In_opt_ HANDLE ExceptionPort,
    _In_ BOOLEAN InJob);

ExternalImport(
    "ntdll.dll",
    RtlCreateProcessParametersEx,
    NTSTATUS,
    _Out_ PRTL_USER_PROCESS_PARAMETERS* pProcessParameters,
    _In_ PUNICODE_STRING ImagePathName,
    _In_opt_ PUNICODE_STRING DllPath,
    _In_opt_ PUNICODE_STRING CurrentDirectory,
    _In_opt_ PUNICODE_STRING CommandLine,
    _In_opt_ PVOID Environment,
    _In_opt_ PUNICODE_STRING WindowTitle,
    _In_opt_ PUNICODE_STRING DesktopInfo,
    _In_opt_ PUNICODE_STRING ShellInfo,
    _In_opt_ PUNICODE_STRING RuntimeData,
    _In_ ULONG Flags);


ExternalImport(
    "ntdll.dll",
    NtCreateThread,
    NTSTATUS,
    _Out_ PHANDLE ThreadHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_ HANDLE ProcessHandle,
    _Out_ PCLIENT_ID ClientId,
    _In_ PCONTEXT ThreadContext,
    _In_ PINITIAL_TEB InitialTeb,
    _In_ BOOLEAN CreateSuspended);

ExternalImport(
    "ntdll.dll",
    NtCreateThreadEx,
    NTSTATUS,
    _Out_ PHANDLE ThreadHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_ HANDLE ProcessHandle,
    _In_ PVOID StartRoutine,
    _In_opt_ PVOID Argument,
    _In_ ULONG CreateFlags,
    _In_ ULONG_PTR ZeroBits,
    _In_opt_ SIZE_T StackSize,
    _In_opt_ SIZE_T MaximumStackSize,
    _In_opt_ PVOID AttributeList);

ExternalImport(
    "ntdll.dll",
    NtCreateSection,
    NTSTATUS,
    OUT PHANDLE SectionHandle,
    IN ULONG DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
    IN PLARGE_INTEGER MaximumSize OPTIONAL,
    IN ULONG PageAttributess,
    IN ULONG SectionAttributes,
    IN HANDLE FileHandle OPTIONAL);


ExternalImport(
    "ntdll.dll",
    NtCreateTransaction,
    NTSTATUS,
    PHANDLE TransactionHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    LPGUID Uow,
    HANDLE TmHandle,
    ULONG CreateOptions,
    ULONG IsolationLevel,
    ULONG IsolationFlags,
    PLARGE_INTEGER Timeout,
    PUNICODE_STRING Description);

ExternalImport(
    "ntdll.dll",
    NtOpenFile,
    NTSTATUS,
    _Out_ PHANDLE FileHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ POBJECT_ATTRIBUTES ObjectAttributes,
    _Out_ PIO_STATUS_BLOCK IoStatusBlock,
    _In_ ULONG ShareAccess,
    _In_ ULONG OpenOptions);

ExternalImport(
    "ntdll.dll",
    NtSetInformationFile,
    NTSTATUS,
    IN HANDLE FileHandle,
    OUT PIO_STATUS_BLOCK IoStatusBlock,
    IN PVOID FileInformation,
    IN ULONG Length,
    IN FILE_INFORMATION_CLASS FileInformationClass);

ExternalImport(
    "ntdll.dll",
    NtQueryInformationFile,
    NTSTATUS,
    IN HANDLE FileHandle,
    OUT PIO_STATUS_BLOCK IoStatusBlock,
    OUT PVOID FileInformation,
    IN ULONG Length,
    IN FILE_INFORMATION_CLASS FileInformationClass);

ExternalImport(
    "ntdll.dll",
    NtOpenDirectoryObject,
    NTSTATUS,
    OUT PHANDLE DirectoryObjectHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes);

ExternalImport(
    "ntdll.dll",
    NtQueryDirectoryObject,
    NTSTATUS,
    _In_ HANDLE DirectoryHandle,
    _Out_opt_ PVOID Buffer,
    _In_ ULONG Length,
    _In_ BOOLEAN ReturnSingleEntry,
    _In_ BOOLEAN RestartScan,
    _Inout_ PULONG Context,
    _Out_opt_ PULONG ReturnLength);

ExternalImport(
    "ntdll.dll",
    AlpcInitializeMessageAttribute,
    NTSTATUS,
    _In_ ULONG AttributeFlags,
    _Out_opt_ PALPC_MESSAGE_ATTRIBUTES Buffer,
    _In_ ULONG BufferSize,
    _Out_ PULONG RequiredBufferSize);


ExternalImport(
    "ntdll.dll",
    NtAlpcConnectPort,
    NTSTATUS,
    __out PHANDLE PortHandle,
    __in PUNICODE_STRING PortName,
    __in_opt POBJECT_ATTRIBUTES ObjectAttributes,
    __in_opt PALPC_PORT_ATTRIBUTES PortAttributes,
    __in ULONG Flags,
    __in_opt PSID RequiredServerSid,
    __inout_opt PPORT_MESSAGE ConnectionMessage,
    __inout_opt PULONG BufferLength,
    __inout_opt PALPC_MESSAGE_ATTRIBUTES OutMessageAttributes,
    __inout_opt PALPC_MESSAGE_ATTRIBUTES InMessageAttributes,
    __in_opt PLARGE_INTEGER Timeout);


ExternalImport(
    "ntdll.dll",
    NtAlpcSendWaitReceivePort,
    NTSTATUS,
    _In_ HANDLE PortHandle,
    _In_ ULONG Flags,
    _In_ PPORT_MESSAGE SendMessage,
    _Inout_opt_ PALPC_MESSAGE_ATTRIBUTES SendMessageAttributes,
    _Out_ PPORT_MESSAGE ReceiveMessage,
    _Inout_opt_ PSIZE_T BufferLength,
    _Inout_opt_ PALPC_MESSAGE_ATTRIBUTES ReceiveMessageAttributes,
    _In_opt_ PLARGE_INTEGER Timeout);


ExternalImport("ntdll.dll", NtAlpcDisconnectPort, NTSTATUS, _In_ HANDLE PortHandle, _In_ ULONG Flags);


ExternalImport(
    "ntdll.dll",
    NtAlpcCreatePort,
    NTSTATUS,
    _Out_ PHANDLE PortHandle,
    _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_opt_ PALPC_PORT_ATTRIBUTES PortAttributes);


ExternalImport(
    "ntdll.dll",
    NtAlpcAcceptConnectPort,
    NTSTATUS,
    _Out_ PHANDLE PortHandle,
    _In_ HANDLE ConnectionPortHandle,
    _In_ ULONG Flags,
    _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_opt_ PALPC_PORT_ATTRIBUTES PortAttributes,
    _In_opt_ PVOID PortContext,
    PPORT_MESSAGE ConnectionRequest,
    _Inout_opt_ PALPC_MESSAGE_ATTRIBUTES ConnectionMessageAttributes,
    _In_ BOOLEAN AcceptConnection);


} // namespace pwn::Resolver::ntdll


namespace pwn::Resolver::kernel32
{
ExternalImport(
    "kernel32.dll",
    CreateFileW,
    HANDLE,
    LPCTSTR lpFileName,
    DWORD dwDesiredAccess,
    DWORD dwShareMode,
    LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    DWORD dwCreationDisposition,
    DWORD dwFlagsAndAttributes,
    HANDLE hTemplateFile);
} // namespace pwn::Resolver::kernel32


namespace pwn::Resolver::dbghelp
{

ExternalImport("dbghelp.dll", SymSetOptions, DWORD, DWORD SymOptions);


ExternalImport("dbghelp.dll", SymInitializeW, BOOL, HANDLE hProcess, PWSTR UserSearchPath, BOOL fInvadeProcess);


ExternalImport(
    "dbghelp.dll",
    SymEnumerateModulesW64,
    BOOL,
    HANDLE hProcess,
    PVOID EnumModulesCallback,
    PVOID UserContext);


ExternalImport(
    "dbghelp.dll",
    SymLoadModuleExW,
    ULONG_PTR,
    HANDLE hProcess,
    HANDLE hFile,
    PCWSTR ImageName,
    PCWSTR ModuleName,
    DWORD64 BaseOfDll,
    DWORD DllSize,
    PVOID ModLoadData,
    DWORD Flags);


ExternalImport(
    "dbghelp.dll",
    SymEnumSymbolsW,
    BOOL,
    HANDLE hProcess,
    ULONG64 BaseOfDll,
    PCWSTR Mask,
    PVOID EnumSymbolsCallback,
    PVOID UserContext);


ExternalImport("dbghelp.dll", SymFromNameW, BOOL, HANDLE hProcess, PCWSTR Name, PVOID /* SYMBOL_INFOW* */ Symbol);


ExternalImport(
    "dbghelp.dll",
    SymFromAddrW,
    BOOL,
    HANDLE hProcess,
    uptr Address,
    uptr* Displacement,
    PVOID /* Symbols::SYMBOL_INFOW* */ Symbol);


ExternalImport("dbghelp.dll", SymSetSearchPathW, BOOL, HANDLE hProcess, PCTSTR SearchPath);


} // namespace pwn::Resolver::dbghelp
