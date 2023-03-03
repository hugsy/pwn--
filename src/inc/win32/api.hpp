#pragma once

#include "resolver.hpp"

namespace pwn::Resolver::ntdll
{
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

} // namespace pwn::Resolver::ntdll
