#include "thread.h"

#include "handle.h"


extern "C" NTSYSAPI NTSTATUS NtSetInformationThread(
	IN HANDLE          ThreadHandle,
	IN THREAD_INFORMATION_CLASS ThreadInformationClass,
	IN PVOID           ThreadInformation,
	IN ULONG           ThreadInformationLength
);


extern NTSYSAPI NTSTATUS NTAPI NtQueryInformationThread(
		IN HANDLE               ThreadHandle,
		IN THREAD_INFORMATION_CLASS ThreadInformationClass,
		OUT PVOID               ThreadInformation,
		IN ULONG                ThreadInformationLength,
		OUT PULONG              ReturnLength OPTIONAL
);


DWORD g_AdminThreadId = 0;


_Success_(return)
bool pwn::thread::start_backdoor()
{
	// TODO
	return true;
}


_Success_(return != nullptr)
std::unique_ptr<std::wstring> pwn::thread::get_name()
{
	// TODO
	return nullptr;
}



_Success_(return)
bool pwn::thread::set_name(_In_ DWORD dwThreadId, _In_ const std::wstring& name)
{
	auto hThread = pwn::generic::GenericHandle(
		::OpenThread(THREAD_SET_LIMITED_INFORMATION, FALSE, dwThreadId)
	);
	if (!hThread)
		return false;

	UNICODE_STRING us;
	us.Length = name.length() & 0xffff;
	us.MaximumLength = 0xffff; // no one cares
	us.Buffer = (PWSTR)name.c_str();

	auto Status = NtSetInformationThread(
		hThread.get(), 
		ThreadNameInformation, 
		&us, 
		sizeof(UNICODE_STRING)
	);
	return NT_SUCCESS(Status);
}


_Success_(return)
bool pwn::thread::set_name(_In_ DWORD dwThreadId, _In_ const PBYTE lpBuffer, _In_ WORD wBufferLength)
{
	auto hThread = pwn::generic::GenericHandle(
		::OpenThread(THREAD_SET_LIMITED_INFORMATION, FALSE, dwThreadId)
	);
	if (!hThread)
		return false;

	UNICODE_STRING us;
	us.Length = wBufferLength;
	us.MaximumLength = wBufferLength;
	us.Buffer = (PWSTR)lpBuffer;

	auto Status = NtSetInformationThread(
		hThread.get(),
		ThreadNameInformation,
		&us,
		sizeof(UNICODE_STRING)
	);
	return NT_SUCCESS(Status);
}
