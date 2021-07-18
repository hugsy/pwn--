#pragma once

#include "common.h"
#include "nt.h"


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
	_Success_(return != nullptr) PWNAPI std::unique_ptr<std::wstring> get_name();
	_Success_(return) PWNAPI bool set_name(_In_ DWORD dwThreadId, _In_ const std::wstring& name);
	_Success_(return) PWNAPI bool set_name(_In_ DWORD dwThreadId, _In_ const PBYTE lpBuffer, _In_ WORD wBufferLength);
}