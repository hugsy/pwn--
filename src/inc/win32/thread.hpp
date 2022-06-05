#pragma once

#include <optional>

#include "common.hpp"
#include "nt.hpp"

extern "C"
{

    NTSTATUS
    NTAPI
    NtSetInformationThread(
        _In_ HANDLE ThreadHandle,
        _In_ THREADINFOCLASS ThreadInformationClass,
        _In_reads_bytes_(ThreadInformationLength) PVOID ThreadInformation,
        _In_ ULONG ThreadInformationLength);

    NTSTATUS NTAPI
    NtQueryInformationThread(
        IN HANDLE ThreadHandle,
        IN THREADINFOCLASS ThreadInformationClass,
        OUT PVOID ThreadInformation,
        IN ULONG ThreadInformationLength,
        OUT PULONG ReturnLength OPTIONAL);
}


namespace pwn::windows::thread
{
_Success_(return != std::nullopt)
PWNAPI auto
get_name(_In_ i32 dwThreadId = -1) -> std::optional<std::wstring>;

_Success_(return )
PWNAPI auto
set_name(_In_ std::wstring const& name, _In_ i32 dwThreadId = -1) -> bool;

} // namespace pwn::windows::thread
