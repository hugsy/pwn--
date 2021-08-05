#pragma once

#include <optional>

#include "common.h"
#include "nt.h"

extern "C"
{
    NTSTATUS NTAPI
    NtSetInformationThread(_In_ HANDLE ThreadHandle, _In_ THREAD_INFORMATION_CLASS ThreadInformationClass, _In_reads_bytes_(ThreadInformationLength) PVOID ThreadInformation, _In_ ULONG ThreadInformationLength);


    NTSTATUS NTAPI
    NtQueryInformationThread(IN HANDLE ThreadHandle, IN THREADINFOCLASS ThreadInformationClass, OUT PVOID ThreadInformation, IN ULONG ThreadInformationLength, OUT PULONG ReturnLength OPTIONAL);
}


namespace pwn::thread
{
_Success_(return != nullptr) PWNAPI auto get_name(_In_ DWORD dwThreadId = -1) -> std::optional<std::wstring>;

_Success_(return ) PWNAPI auto set_name(_In_ std::wstring const& name, _In_ DWORD dwThreadId = -1) -> bool;

} // namespace pwn::thread
