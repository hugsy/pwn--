#pragma once

#include "common.h"
#include "nt.h"

#include <optional>

extern "C"
{
    NTSTATUS NTAPI
    NtSetInformationThread(
        _In_ HANDLE ThreadHandle, 
        _In_ THREAD_INFORMATION_CLASS ThreadInformationClass,
        _In_reads_bytes_(ThreadInformationLength) PVOID ThreadInformation,
        _In_ ULONG ThreadInformationLength
    );


    NTSTATUS NTAPI NtQueryInformationThread(
        IN HANDLE ThreadHandle, 
        IN THREADINFOCLASS ThreadInformationClass,
        OUT PVOID ThreadInformation,
        IN ULONG ThreadInformationLength,
        OUT PULONG ReturnLength OPTIONAL
    );
}


namespace pwn::thread
{
	_Success_(return) PWNAPI bool start_backdoor();
	_Success_(return != nullptr) PWNAPI std::optional<std::wstring> get_name(_In_ DWORD dwThreadId = -1);
    _Success_(return ) PWNAPI bool set_name(_In_ std::wstring const& name, _In_ DWORD dwThreadId = -1);
    }