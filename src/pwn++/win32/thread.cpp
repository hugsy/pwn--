#include "win32/thread.hpp"

#include "handle.hpp"
#include "log.hpp"
#include "utils.hpp"

#define WINDOWS_VERSION_1607 14393


Result<bool>
pwn::windows::Thread::ReOpenHandleWith(DWORD DesiredAccess)
{
    m_ThreadHandle = pwn::UniqueHandle {::OpenThread(DesiredAccess, 0, m_Tid)};
    if ( !m_ThreadHandle )
    {
        return Err(ErrorCode::PermissionDenied);
    }

    return Ok(true);
}


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
    if(! m_ThreadHandle)
    {
        auto res = ReOpenHandleWith(TOKEN_QUERY);
        if(Failed(res))
        {
            return res;
        }
    }

    NTSTATUS Status              = STATUS_UNSUCCESSFUL;
    ULONG CurrentSize            = sizeof(UNICODE_STRING);
    ULONG ReturnedSize           = 0;
    std::unique_ptr<u8[]> Buffer = nullptr;

    do
    {
        Buffer = std::make_unique<u8[]>(CurrentSize);
        Status =
            ::NtQueryInformationThread(m_ThreadHandle.get(), ThreadNameInformation, Buffer.get(), CurrentSize, &ReturnedSize);

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
    if(! m_ThreadHandle)
    {
        auto res = ReOpenHandleWith(TOKEN_SET_LIMITED_INFORMATION);
        if(Failed(res))
        {
            return res;
        }
    }

    if ( name.size() >= 0xffff )
    {
        return Err(ErrorCode::BufferTooBig);
    }

    //
    // Make sure we're on 1607+
    //
    auto const Version = pwn::windows::system::version();
    if(!Version)
    {
        return Err(ErrorCode::UnknownError);
    }

    const BuildNumber = Version.get<3>();
    if(BuildNumber < WINDOWS_VERSION_1607)
    {
        return Err(ErrorCode::BadVersion);
    }

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
