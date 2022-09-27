#include "win32/thread.hpp"

#include <tlhelp32.h>

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

namespace pwn::windows
{

Result<bool>
Thread::ReOpenHandleWith(DWORD DesiredAccess)
{
    //
    // If we already have the sufficient rights, skip
    //
    if ( (m_ThreadHandleAccessMask & DesiredAccess) == DesiredAccess )
    {
        return Ok(true);
    }

    //
    // Otherwise, try to get it
    //
    u32 NewAccessMask = m_ThreadHandleAccessMask | DesiredAccess;
    HANDLE hThread    = ::OpenThread(NewAccessMask, false, m_Tid);
    if ( hThread == nullptr )
    {
        log::perror(L"OpenThread()");
        return Err(ErrorCode::PermissionDenied);
    }

    m_ThreadHandle           = pwn::UniqueHandle {hThread};
    m_ThreadHandleAccessMask = NewAccessMask;
    return Ok(true);
}

u32 const
Thread::ThreadId() const
{
    return m_Tid;
}

Result<std::wstring>
Thread::Name()
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
    auto res = ReOpenHandleWith(THREAD_QUERY_LIMITED_INFORMATION);
    if ( Failed(res) )
    {
        return Err(Error(res).code);
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
                return Ok(std::wstring {});
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
Thread::Name(std::wstring const& name)
{
    auto res = ReOpenHandleWith(THREAD_SET_LIMITED_INFORMATION);
    if ( Failed(res) )
    {
        return res;
    }

    if ( name.size() >= 0xffff )
    {
        return Err(ErrorCode::BufferTooBig);
    }

    //
    // Make sure we're on 1607+
    //
    auto const Version     = pwn::windows::system::WindowsVersion();
    const auto BuildNumber = std::get<2>(Version);
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


Result<Thread>
Thread::Current()
{
    SharedHandle hProcess = std::make_shared<UniqueHandle>(UniqueHandle {::GetCurrentProcess()});
    auto t                = Thread(::GetCurrentThreadId(), hProcess);
    if ( !t.IsValid() )
    {
        return Err(ErrorCode::InitializationFailed);
    }
    return Ok(t);
}


Result<std::shared_ptr<u8[]>>
Thread::Query(THREADINFOCLASS ThreadInformationClass)
{
    ULONG ReturnLength = 0;

    //
    // Request the structure size
    //
    NTSTATUS Status = STATUS_SUCCESS;
    Status = ::NtQueryInformationThread(m_ThreadHandle.get(), ThreadInformationClass, nullptr, 0, &ReturnLength);
    if ( Status != STATUS_INFO_LENGTH_MISMATCH )
    {
        return Err(ErrorCode::PermissionDenied);
    }

    //
    // Prepare the structure and get the information
    //
    const ULONG BufferSize = ReturnLength;
    auto Buffer            = std::make_shared<u8[]>(BufferSize);
    Status                 = ::NtQueryInformationThread(
        m_ThreadHandle.get(),
        ThreadInformationClass,
        Buffer.get(),
        BufferSize,
        &ReturnLength);
    if ( !NT_SUCCESS(Status) )
    {
        return Err(ErrorCode::PermissionDenied);
    }

    return Ok(Buffer);
}


Result<std::vector<u32>>
ThreadGroup::List()
{
    auto h = UniqueHandle {::CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0)};
    if ( !h )
    {
        log::perror(L"CreateToolhelp32Snapshot()");
        return Err(ErrorCode::ExternalApiCallFailed);
    }

    std::vector<u32> tids;
    const u32 Pid    = pwn::windows::system::ProcessId(m_ProcessHandle->get());
    THREADENTRY32 te = {0};
    te.dwSize        = sizeof(te);
    if ( ::Thread32First(h.get(), &te) )
    {
        do
        {
            if ( !(te.dwSize >= FIELD_OFFSET(THREADENTRY32, th32OwnerProcessID) + sizeof(te.th32OwnerProcessID)) )
                continue;
            if ( !te.th32ThreadID )
                continue;

            if ( te.th32OwnerProcessID != Pid )
                continue;

            tids.push_back(te.th32ThreadID);

            te.dwSize = sizeof(te);
        } while ( ::Thread32Next(h.get(), &te) );
    }

    return Ok(tids);
}

Thread
ThreadGroup::operator[](const u32 Tid)
{
    return Thread(Tid, m_ProcessHandle);
}

} // namespace pwn::windows
