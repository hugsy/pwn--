#include "win32/thread.hpp"

#include "handle.hpp"
#include "log.hpp"
#include "utils.hpp"


Result<std::wstring>
pwn::windows::Thread::Name()
{
    //
    // Is name in cache, just return it
    //
    if ( m_Name.has_value() )
    {
        return Ok(m_Name.value());
    }

    //
    // Otherwise invoke NtQueryInformationThread(ThreadNameInformation)
    //
    auto hThread = pwn::UniqueHandle {::OpenThread(THREAD_QUERY_LIMITED_INFORMATION, 0, m_Tid)};
    if ( !hThread )
    {
        return Err(ErrorCode::ExternalApiCallFailed);
    }

    NTSTATUS Status              = STATUS_UNSUCCESSFUL;
    ULONG CurrentSize            = sizeof(UNICODE_STRING);
    ULONG ReturnedSize           = 0;
    std::unique_ptr<u8[]> Buffer = nullptr;

    do
    {
        Buffer = std::make_unique<u8[]>(CurrentSize);
        Status =
            ::NtQueryInformationThread(hThread.get(), ThreadNameInformation, Buffer.get(), CurrentSize, &ReturnedSize);

        if ( NT_SUCCESS(Status) )
        {
            //
            // No name
            //
            if ( ReturnedSize == 0 )
            {
                return Ok(L"");
            }

            //
            // Otherwise, a name was found
            //
            break;
        }

        //
        // If there's a name, expect STATUS_BUFFER_TOO_SMALL
        //
        if ( Status != STATUS_BUFFER_TOO_SMALL )
        {
            pwn::log::ntperror(L"NtQueryInformationThread(ThreadNameInformation)", Status);
            return Err(ErrorCode::ExternalApiCallFailed);
        }

        CurrentSize = ReturnedSize;
    } while ( true );

    //
    // Create a wstring from the UNICODE_STRING pointer
    //
    const PUNICODE_STRING usThreadName = reinterpret_cast<PUNICODE_STRING>(Buffer.get());
    return Ok(std::wstring(usThreadName->Buffer, usThreadName->Length / sizeof(wchar_t)));
}


Result<bool>
pwn::windows::Thread::Name(std::wstring const& name)
{
    auto hThread = pwn::UniqueHandle {::OpenThread(THREAD_SET_LIMITED_INFORMATION, 0, m_Tid)};
    if ( !hThread )
    {
        return Err(ErrorCode::ExternalApiCallFailed);
    }

    if ( name.size() >= 0xffff )
    {
        return Err(ErrorCode::BufferTooBig);
    }

    // TODO: check if version >=  win10-1607

    //
    // Set the thread name
    //
    UNICODE_STRING usThreadName = {0};
    ::RtlInitUnicodeString(&usThreadName, (PWSTR)name.c_str());
    auto Status = ::NtSetInformationThread(hThread.get(), ThreadNameInformation, &usThreadName, sizeof(UNICODE_STRING));
    if ( NT_SUCCESS(Status) )
    {
        return Ok(true);
    }

    pwn::log::ntperror(L"NtSetInformationThread(ThreadNameInformation) failed", Status);
    return Err(ErrorCode::ExternalApiCallFailed);
}
