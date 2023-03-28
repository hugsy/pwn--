#include "Win32/Thread.hpp"

#include <tlhelp32.h>

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

#ifndef _M_ARM64
bool
GetTeb(uptr* teb);

usize
GetTebLength();
#else
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

Thread::Thread(u32 Tid, std::shared_ptr<Process> const& Process) :
    m_Tid {Tid},
    m_Valid {false},

    m_ThreadHandle {nullptr},
    m_ThreadHandleAccessMask {0},
    m_Teb {0},
    Token {}
{
    if ( !Process )
    {
        throw std::runtime_error("Process cannot be null");
    }

    m_Process       = Process;
    m_ProcessHandle = m_Process->Handle();

    m_IsSelf = (m_Tid == ::GetCurrentThreadId());

    if ( Success(ReOpenThreadWith(THREAD_QUERY_INFORMATION)) )
    {
        m_Valid = (m_ThreadHandle != nullptr);
        Token   = Security::Token(m_ThreadHandle, Security::Token::TokenType::Thread);
    }
}


Thread::Thread(Thread const& OldCopy)
{
    m_Process                = OldCopy.m_Process;
    m_ProcessHandle          = OldCopy.m_ProcessHandle;
    m_ThreadHandle           = OldCopy.m_ThreadHandle;
    m_Tid                    = OldCopy.m_Tid;
    m_Teb                    = OldCopy.m_Teb;
    m_Name                   = OldCopy.m_Name;
    m_IsSelf                 = OldCopy.m_IsSelf;
    m_ThreadHandleAccessMask = OldCopy.m_ThreadHandleAccessMask;
    Token                    = Security::Token(m_ThreadHandle, Security::Token::TokenType::Thread);
    m_Valid                  = (m_ThreadHandle != nullptr);
}


Thread&
Thread::operator=(Thread const& OldCopy)
{
    m_Process                = OldCopy.m_Process;
    m_ProcessHandle          = OldCopy.m_ProcessHandle;
    m_ThreadHandle           = OldCopy.m_ThreadHandle;
    m_Tid                    = OldCopy.m_Tid;
    m_Teb                    = OldCopy.m_Teb;
    m_Name                   = OldCopy.m_Name;
    m_IsSelf                 = OldCopy.m_IsSelf;
    m_ThreadHandleAccessMask = OldCopy.m_ThreadHandleAccessMask;
    Token                    = Security::Token(m_ThreadHandle, Security::Token::TokenType::Thread);
    m_Valid                  = (m_ThreadHandle != nullptr);
    return *this;
}


bool
Thread::IsValid() const
{
    return m_Valid;
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
        return Err(ErrorCode::PermissionDenied);
    }

    SharedHandle New = std::make_shared<UniqueHandle>(UniqueHandle {hThread});
    m_ThreadHandle.swap(New);
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
    // Make sure we're on 1607+
    //
    auto const Version     = System::System::WindowsVersion();
    const auto BuildNumber = std::get<2>(Version);
    if ( BuildNumber < WINDOWS_VERSION_1607 )
    {
        return Err(ErrorCode::BadVersion);
    }

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
    auto res = ReOpenThreadWith(THREAD_QUERY_LIMITED_INFORMATION);
    if ( Failed(res) )
    {
        return Err(ErrorCode::PermissionDenied);
    }

    NTSTATUS Status              = STATUS_UNSUCCESSFUL;
    ULONG CurrentSize            = sizeof(UNICODE_STRING);
    ULONG ReturnedSize           = 0;
    std::unique_ptr<u8[]> Buffer = nullptr;

    do
    {
        Buffer = std::make_unique<u8[]>(CurrentSize);
        Status = ::NtQueryInformationThread(
            m_ThreadHandle->get(),
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
            Log::ntperror(L"NtQueryInformationThread(ThreadNameInformation)", Status);
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
    auto res = ReOpenThreadWith(THREAD_SET_LIMITED_INFORMATION);
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
    auto const Version     = System::System::WindowsVersion();
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
        ::NtSetInformationThread(m_ThreadHandle->get(), ThreadNameInformation, &usThreadName, sizeof(UNICODE_STRING));
    if ( NT_SUCCESS(Status) )
    {
        return Ok(true);
    }

    Log::ntperror(L"NtSetInformationThread(ThreadNameInformation) failed", Status);
    return Err(ErrorCode::ExternalApiCallFailed);
}


Result<Thread>
Thread::Current()
{
    Process CurrentProcess;

    auto res = Process::Current();
    if ( Failed(res) )
    {
        return Err(Error(res).code);
    }

    auto CurrentThread = Value(res).Threads.at(::GetCurrentThreadId());
    if ( !CurrentThread.IsValid() )
    {
        return Err(ErrorCode::InitializationFailed);
    }
    return Ok(CurrentThread);
}


Result<PVOID>
Thread::QueryInternal(const THREADINFOCLASS ThreadInformationClass, const usize InitialSize)
{
    usize Size         = InitialSize;
    ULONG ReturnLength = 0;
    NTSTATUS Status    = STATUS_SUCCESS;
    auto Buffer        = ::LocalAlloc(LPTR, Size);
    if ( !Buffer )
    {
        return Err(ErrorCode::AllocationError);
    }

    do
    {
        Status = ::NtQueryInformationThread(m_ThreadHandle->get(), ThreadInformationClass, Buffer, Size, &ReturnLength);
        if ( NT_SUCCESS(Status) )
        {
            return Ok(Buffer);
        }

        if ( Status == STATUS_INFO_LENGTH_MISMATCH )
        {
            HLOCAL NewBuffer = ::LocalReAlloc(Buffer, ReturnLength, LMEM_MOVEABLE | LMEM_ZEROINIT);
            if ( NewBuffer )
            {
                Buffer = NewBuffer;
                Size   = ReturnLength;
                continue;
            }
        }

        Log::ntperror(L"NtQueryInformationThread()", Status);
        break;

    } while ( true );

    ::LocalFree(Buffer);
    return Err(ErrorCode::ExternalApiCallFailed);
}

PTEB
Thread::ThreadInformationBlock()
{
    if ( m_Teb )
    {
        return m_Teb;
    }

    if ( m_IsSelf )
    {
        uptr teb = 0;
        if ( GetTeb(&teb) == true )
        {
            m_Teb = (PTEB)teb;
        }
    }
    else
    {
        const uptr pfnGetTeb     = (uptr)&GetTeb;
        const usize pfnGetTebLen = GetTebLength();

        auto res = m_Process->Execute(pfnGetTeb, pfnGetTebLen);
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
