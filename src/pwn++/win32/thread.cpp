#include "win32/thread.hpp"

#include "handle.hpp"
#include "log.hpp"
#include "system.hpp"
#include "utils.hpp"

#define WINDOWS_VERSION_1507 10240
#define WINDOWS_VERSION_1511 10586
#define WINDOWS_VERSION_1607 14393
#define WINDOWS_VERSION_1703 15063
#define WINDOWS_VERSION_1709 16299
#define WINDOWS_VERSION_1803 17134
#define WINDOWS_VERSION_1809 17763
#define WINDOWS_VERSION_1903 18362
#define WINDOWS_VERSION_1909 18363
#define WINDOWS_VERSION_2004 19041
#define WINDOWS_VERSION_20H2 19042
#define WINDOWS_VERSION_21H1 19043
#define WINDOWS_VERSION_21H2 19044
#define WINDOWS_VERSION_22H2 19045

EXTERN_C_START
bool
GetTeb(uptr* teb);

usize
GetTebLength();
EXTERN_C_END

#ifdef _WIN64
#define TEB_OFFSET 0x30
#else
#define TEB_OFFSET 0x18
#endif

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
    if ( !m_ThreadHandle )
    {
        auto res = ReOpenHandleWith(THREAD_QUERY_LIMITED_INFORMATION);
        if ( Failed(res) )
        {
            return Err(Error(res).code);
        }
    }

    NTSTATUS Status              = STATUS_UNSUCCESSFUL;
    ULONG CurrentSize            = sizeof(UNICODE_STRING);
    ULONG ReturnedSize           = 0;
    std::unique_ptr<u8[]> Buffer = nullptr;

    do
    {
        Buffer = std::make_unique<u8[]>(CurrentSize);
        Status = ::NtQueryInformationThread(
            m_ThreadHandle.get(),
            ThreadNameInformation,
            Buffer.get(),
            CurrentSize,
            &ReturnedSize);

        if ( NT_SUCCESS(Status) )
        {
            //
            // No name
            //
            if ( ReturnedSize == 0 )
            {
                return Ok(std::move(std::wstring {}));
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
    if ( !m_ThreadHandle )
    {
        auto res = ReOpenHandleWith(THREAD_SET_LIMITED_INFORMATION);
        if ( Failed(res) )
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

    const auto BuildNumber = std::get<2>(Version);
    info(L"B = {}", BuildNumber);
    if ( BuildNumber < WINDOWS_VERSION_1607 )
    {
        return Err(ErrorCode::BadVersion);
    }

    //
    // Set the thread name
    //
    UNICODE_STRING usThreadName = {0};
    ::RtlInitUnicodeString(&usThreadName, (PWSTR)name.c_str());
    auto Status =
        ::NtSetInformationThread(m_ThreadHandle.get(), ThreadNameInformation, &usThreadName, sizeof(UNICODE_STRING));
    if ( NT_SUCCESS(Status) )
    {
        return Ok(true);
    }

    log::ntperror(L"NtSetInformationThread(ThreadNameInformation) failed", Status);
    return Err(ErrorCode::ExternalApiCallFailed);
}
