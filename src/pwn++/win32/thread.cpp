#include "win32/thread.hpp"

#include "handle.hpp"
#include "log.hpp"
#include "utils.hpp"

_Success_(return != std::nullopt)
auto
pwn::win::thread::get_name(_In_ i32 dwThreadId) -> std::optional<std::wstring>
{
    HANDLE ThreadHandle = INVALID_HANDLE_VALUE;

    if ( dwThreadId == -1 )
    {
        ThreadHandle = ::GetCurrentThread();
    }
    else
    {
        ThreadHandle = ::OpenThread(THREAD_QUERY_LIMITED_INFORMATION, 0, dwThreadId);
    }

    auto hThread = pwn::utils::GenericHandle(ThreadHandle);
    if ( !hThread )
    {
        return std::nullopt;
    }

    UNICODE_STRING us    = {0};
    ULONG ReturnedLength = 0;
    auto Status          = ::NtQueryInformationThread(
        hThread.get(),
        (THREADINFOCLASS)ThreadNameInformation,
        &us,
        sizeof(UNICODE_STRING),
        &ReturnedLength);

    // empty value ?
    if ( NT_SUCCESS(Status) )
    {
        return std::nullopt;
    }

    // buffer too small ?
    if ( Status != STATUS_BUFFER_TOO_SMALL || ReturnedLength < sizeof(UNICODE_STRING) )
    {
        pwn::log::ntperror(L"NtQueryInformationThread1()", Status);
        return std::nullopt;
    }

    auto buffer = std::make_unique<u8[]>(ReturnedLength);

    Status = ::NtQueryInformationThread(
        hThread.get(),
        (THREADINFOCLASS)ThreadNameInformation,
        buffer.get(),
        ReturnedLength,
        nullptr);
    if ( !NT_SUCCESS(Status) )
    {
        pwn::log::ntperror(L"NtQueryInformationThread2()", Status);
        return std::nullopt;
    }

    auto u = reinterpret_cast<PUNICODE_STRING>(buffer.get());
    return std::wstring(u->Buffer, u->Length / sizeof(wchar_t));
}


_Success_(return )
auto
pwn::win::thread::set_name(_In_ std::wstring const& name, _In_ i32 dwThreadId) -> bool
{
    HANDLE ThreadHandle = INVALID_HANDLE_VALUE;

    if ( dwThreadId == -1 )
    {
        ThreadHandle = ::GetCurrentThread();
    }
    else
    {
        ThreadHandle = ::OpenThread(THREAD_SET_LIMITED_INFORMATION, 0, dwThreadId);
    }

    auto hThread = pwn::utils::GenericHandle(ThreadHandle);
    if ( !hThread )
    {
        return false;
    }


    if ( name.size() >= 0xffff )
    {
        return false;
    }

    UNICODE_STRING us = {0};
    ::RtlInitUnicodeString(&us, (PWSTR)name.c_str());

    auto Status = ::NtSetInformationThread(hThread.get(), ThreadNameInformation, &us, sizeof(UNICODE_STRING));

    return !!(Status == STATUS_SUCCESS);
}
