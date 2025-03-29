// #include <tlhelp32.h>

#include "Win32/Thread.hpp"

#include "Handle.hpp"
#include "Log.hpp"
#include "Utils.hpp"
#include "Win32/System.hpp"

constexpr int WINDOWS_VERSION_1507 = 10240;
constexpr int WINDOWS_VERSION_1511 = 10586;
constexpr int WINDOWS_VERSION_1607 = 14393;
constexpr int WINDOWS_VERSION_1703 = 15063;
constexpr int WINDOWS_VERSION_1709 = 16299;
constexpr int WINDOWS_VERSION_1803 = 17134;
constexpr int WINDOWS_VERSION_1809 = 17763;
constexpr int WINDOWS_VERSION_1903 = 18362;
constexpr int WINDOWS_VERSION_1909 = 18363;
constexpr int WINDOWS_VERSION_2004 = 19041;
constexpr int WINDOWS_VERSION_20H2 = 19042;
constexpr int WINDOWS_VERSION_21H1 = 19043;
constexpr int WINDOWS_VERSION_21H2 = 19044;
constexpr int WINDOWS_VERSION_22H2 = 19045;

EXTERN_C_START

#if defined(_ARM64_) || defined(_ARM_)

//
// TODO those are not working yet
//

bool
GetTeb(uptr* teb)
{
    return false;
}

usize
GetTebLength()
{
    return 0;
}

#else
bool
GetTeb(uptr* teb);

usize
GetTebLength();
#endif // _M_ARM64
EXTERN_C_END

#ifdef _WIN64
#define TEB_OFFSET 0x30
#else
#define TEB_OFFSET 0x18
#endif

namespace pwn::Process
{

std::string
ThreadAccessToString(u32 ThreadAccess)
{
    std::ostringstream str {};
    u32 found {0};
#define CheckAccessAndAppend(x)                                                                                        \
    {                                                                                                                  \
        if ( (ThreadAccess & x) == x )                                                                                 \
        {                                                                                                              \
            str << #x;                                                                                                 \
            found += x;                                                                                                \
        }                                                                                                              \
    }

    CheckAccessAndAppend(THREAD_TERMINATE);
    CheckAccessAndAppend(THREAD_SUSPEND_RESUME);
    CheckAccessAndAppend(THREAD_GET_CONTEXT);
    CheckAccessAndAppend(THREAD_SET_CONTEXT);
    CheckAccessAndAppend(THREAD_QUERY_INFORMATION);
    CheckAccessAndAppend(THREAD_SET_INFORMATION);
    CheckAccessAndAppend(THREAD_SET_THREAD_TOKEN);
    CheckAccessAndAppend(THREAD_IMPERSONATE);
    CheckAccessAndAppend(THREAD_DIRECT_IMPERSONATION);
    CheckAccessAndAppend(THREAD_SET_LIMITED_INFORMATION);
    CheckAccessAndAppend(THREAD_QUERY_LIMITED_INFORMATION);
    CheckAccessAndAppend(THREAD_RESUME);
#undef CheckAccessAndAppend

    if ( found != ThreadAccess )
    {
        str << std::hex << (ThreadAccess - found);
    }

    return str.str();
}


#pragma region Thread

Thread::Thread(u32 Tid, u32 Pid) : m_Tid {Tid}, m_Pid {Pid}
{
    if ( Failed(ReOpenThreadWith(THREAD_QUERY_INFORMATION)) )
    {
        throw std::runtime_error("Thread initialization failed");
    }

    if ( !m_Pid )
    {
        auto res = Query<THREAD_BASIC_INFORMATION>(THREADINFOCLASS::ThreadBasicInformation);
        if ( Failed(res) )
        {
            throw std::runtime_error("Failed to determine the ProcessId");
        }

        auto BasicInfo = Value(std::move(res));
        m_Pid          = HandleToULong(BasicInfo->ClientId.UniqueProcess);
    }
}


Result<bool>
Thread::ReOpenThreadWith(DWORD DesiredAccess)
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
        Log::perror(L"OpenThread()");
        return Err(Error::PermissionDenied);
    }

    m_ThreadHandle           = UniqueHandle {hThread};
    m_ThreadHandleAccessMask = NewAccessMask;
    return Ok(true);
}


Result<std::wstring>
Thread::Name()
{
    //
    // Make sure we're on 1607+
    //
    auto const Version     = System::WindowsVersion();
    const auto BuildNumber = std::get<2>(Version);
    if ( BuildNumber < WINDOWS_VERSION_1607 )
    {
        return Err(Error::BadVersion);
    }

    //
    // Otherwise invoke NtQueryInformationThread(ThreadNameInformation)
    //
    if ( Failed(ReOpenThreadWith(THREAD_QUERY_LIMITED_INFORMATION)) )
    {
        return Err(Error::PermissionDenied);
    }

    auto res = Query<THREAD_NAME_INFORMATION>(THREADINFOCLASS::ThreadNameInformation);
    if ( Failed(res) )
    {
        return Err(Error::ExternalApiCallFailed);
    }

    const std::unique_ptr<THREAD_NAME_INFORMATION> name = Value(std::move(res));
    return Ok(std::wstring(name->ThreadName.Buffer, name->ThreadName.Length / sizeof(wchar_t)));
}


Result<bool>
Thread::Name(std::wstring_view name)
{
    auto res = ReOpenThreadWith(THREAD_SET_LIMITED_INFORMATION);
    if ( Failed(res) )
    {
        return res;
    }

    if ( name.size() >= 0xffff )
    {
        return Err(Error::BufferTooBig);
    }

    //
    // Make sure we're on 1607+
    //
    auto const Version     = System::WindowsVersion();
    const auto BuildNumber = std::get<2>(Version);
    if ( BuildNumber < WINDOWS_VERSION_1607 )
    {
        return Err(Error::BadVersion);
    }

    //
    // Set the thread name
    //
    UNICODE_STRING usThreadName = {0};
    ::RtlInitUnicodeString(&usThreadName, (PWSTR)(name.data()));

    auto Status =
        ::NtSetInformationThread(m_ThreadHandle.get(), ThreadNameInformation, &usThreadName, sizeof(UNICODE_STRING));
    if ( !NT_SUCCESS(Status) )
    {
        Log::ntperror(L"NtSetInformationThread(ThreadNameInformation) failed", Status);
        return Err(Error::ExternalApiCallFailed);
    }
    return Ok(true);
}


Thread
Thread::Current()
{
    return pwn::Process::Thread(::GetCurrentThreadId(), ::GetCurrentProcessId());
}


Result<std::unique_ptr<u8[]>>
Thread::QueryInternal(const THREADINFOCLASS ThreadInformationClass, const usize InitialSize)
{
    usize Size  = InitialSize;
    auto Buffer = std::make_unique<u8[]>(Size);
    if ( !Buffer )
    {
        return Err(Error::AllocationError);
    }

    do
    {
        ULONG ReturnLength = 0;
        NTSTATUS Status =
            ::NtQueryInformationThread(m_ThreadHandle.get(), ThreadInformationClass, Buffer.get(), Size, &ReturnLength);
        if ( NT_SUCCESS(Status) )
        {
            break;
        }

        switch ( Status )
        {
        case STATUS_INFO_LENGTH_MISMATCH:
        case STATUS_BUFFER_TOO_SMALL:
        {
            Size   = ReturnLength;
            Buffer = std::make_unique<u8[]>(Size);
            continue;
        }
        default:
            break;
        }

        Log::ntperror(L"NtQueryInformationThread()", Status);
        return Err(Error::ExternalApiCallFailed);
    } while ( true );

    return Ok(std::move(Buffer));
}


PTEB
Thread::ThreadInformationBlock()
{
    if ( m_Teb ) [[likely]]
    {
        return m_Teb;
    }

    if ( !IsRemote() )
    {
        uptr teb = 0;
        if ( GetTeb(&teb) == true )
        {
            m_Teb = reinterpret_cast<PTEB>(teb);
        }
    }
    else
    {
        const uptr pfnGetTeb     = (uptr)&GetTeb;
        const usize pfnGetTebLen = GetTebLength();

        auto RemoteProcess = Process::Process(m_Pid);
        auto res           = RemoteProcess.Execute(pfnGetTeb, pfnGetTebLen);
        if ( Success(res) )
        {
            m_Teb = reinterpret_cast<PTEB>(Value(res));
        }
    }

    if ( !m_Teb )
    {
        warn(L"TEB was not found");
    }

    return m_Teb;
}

#pragma endregion Thread

} // namespace pwn::Process
