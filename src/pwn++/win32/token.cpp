#include "token.hpp"

#include "log.hpp"
#include "utils.hpp"

namespace pwn::windows
{

bool
Token::IsValid() const
{
    return m_ProcessHandle != nullptr;
}


Result<bool>
Token::ReOpenTokenWithAccess(const DWORD DesiredAccess)
{
    HANDLE h = nullptr;
    if ( IsValid() && ::OpenProcessToken(m_ProcessHandle->get(), DesiredAccess, &h) )
    {
        m_ProcessTokenHandle = pwn::UniqueHandle {h};
        return Ok(true);
    }
    return Err(ErrorCode::PermissionDenied);
}


Result<PVOID>
Token::QueryInternal(const TOKEN_INFORMATION_CLASS TokenInformationClass, const usize InitialSize)
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
        Status =
            ::NtQueryInformationToken(m_ProcessTokenHandle.get(), TokenInformationClass, Buffer, Size, &ReturnLength);
        if ( NT_SUCCESS(Status) )
        {
            break;
        }

        if ( Status == STATUS_INFO_LENGTH_MISMATCH )
        {
            Size   = ReturnLength;
            Buffer = ::LocalReAlloc(Buffer, Size, LMEM_ZEROINIT);
            continue;
        }

        log::ntperror(L"NtQueryInformationToken()", Status);
        return Err(ErrorCode::PermissionDenied);

    } while ( true );

    return Ok(Buffer);
}


Result<bool>
Token::IsElevated()
{
    auto res = Query<TOKEN_ELEVATION>(TokenElevation);
    if ( Failed(res) )
    {
        return Err(Error(res).code);
    }

    return Ok(Value(res)->TokenIsElevated == 1);
}


Result<bool>
Token::EnumeratePrivileges()
{
    auto res = Query<TOKEN_PRIVILEGES>(TokenPrivileges);
    if ( Failed(res) )
    {
        return Err(Error(res).code);
    }

    const auto Privs           = Value(res);
    const DWORD PrivilegeCount = Privs->PrivilegeCount;
    dbg(L"{} privileges", PrivilegeCount);
    for ( u32 i = 0; i < PrivilegeCount; i++ )
    {
        const PLUID_AND_ATTRIBUTES Priv = &(Privs->Privileges[i]);
    }

    return Ok(Privs->PrivilegeCount > 0);
}

} // namespace pwn::windows
