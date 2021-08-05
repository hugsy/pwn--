#include "thread.h"

#include "handle.h"
#include "utils.h"


_Success_(return != std::nullopt) 
std::optional<std::wstring>
pwn::thread::get_name(_In_ DWORD dwThreadId)
{
    HANDLE ThreadHandle = INVALID_HANDLE_VALUE;

    if (dwThreadId == (DWORD)-1)
    {
        ThreadHandle = ::GetCurrentThread();
    }
    else
    {
        ThreadHandle = ::OpenThread(THREAD_QUERY_LIMITED_INFORMATION, 0, dwThreadId);
    }

    auto hThread = pwn::utils::GenericHandle(ThreadHandle);
    if (!hThread)
    {
        return std::nullopt;
    }

    UNICODE_STRING us    = {0};
    ULONG ReturnedLength = 0;
    auto Status          = ::NtQueryInformationThread(hThread.get(), (THREADINFOCLASS)ThreadNameInformation, &us, sizeof(UNICODE_STRING), &ReturnedLength);

    // empty value ?
    if (NT_SUCCESS(Status))
    {
        return std::nullopt;
    }

    // buffer too small ?
    if (Status != STATUS_BUFFER_TOO_SMALL || ReturnedLength < sizeof(UNICODE_STRING))
    {
        pwn::log::ntperror(L"NtQueryInformationThread1()", Status);
        return std::nullopt;
    }

    auto buffer = std::make_unique<BYTE[]>(ReturnedLength);

    Status = ::NtQueryInformationThread(hThread.get(), (THREADINFOCLASS)ThreadNameInformation, buffer.get(), ReturnedLength, nullptr);

    if (!NT_SUCCESS(Status))
    {
        pwn::log::ntperror(L"NtQueryInformationThread2()", Status);
        return std::nullopt;
    }

    auto u = reinterpret_cast<PUNICODE_STRING>(buffer.get());
    return std::wstring(u->Buffer, u->Length);
}


_Success_(return) bool pwn::thread::set_name(_In_ std::wstring const &name, _In_ DWORD dwThreadId)
{
    HANDLE ThreadHandle = INVALID_HANDLE_VALUE;

    if (dwThreadId == (DWORD)-1)
    {
        ThreadHandle = ::GetCurrentThread();
    }
    else
    {
        ThreadHandle = ::OpenThread(THREAD_SET_LIMITED_INFORMATION, 0, dwThreadId);
    }

    auto hThread = pwn::utils::GenericHandle(ThreadHandle);
    if (!hThread)
    {
        return false;
    }


    if (name.size() >= 0xffff)
    {
        return false;
    }

    UNICODE_STRING us = {0};
    ::RtlInitUnicodeString(&us, (PWSTR)name.c_str());

    auto Status = ::NtSetInformationThread(hThread.get(), ThreadNameInformation, &us, sizeof(UNICODE_STRING));
    return SUCCEEDED(Status);
}
