#include "token.hpp"

#include "log.hpp"
#include "utils.hpp"

namespace pwn::windows
{

bool
Token::IsValid() const
{
    return m_ProcessOrThreadHandle != nullptr;
}


Result<bool>
Token::ReOpenTokenWith(const DWORD DesiredAccess)
{
    if ( IsValid() == false )
    {
        return Err(ErrorCode::InvalidState);
    }

    if ( (m_TokenAccessMask & DesiredAccess) == DesiredAccess )
    {
        return Ok(true);
    }

    HANDLE hToken          = nullptr;
    DWORD NewDesiredAccess = m_TokenAccessMask | DesiredAccess;

    BOOL bRes = FALSE;
    switch ( m_Type )
    {
    case TokenType::Process:
        bRes = ::OpenProcessToken(m_ProcessOrThreadHandle->get(), NewDesiredAccess, &hToken);
        break;
    case TokenType::Thread:
        bRes = ::OpenThreadToken(m_ProcessOrThreadHandle->get(), NewDesiredAccess, true, &hToken);
        break;
    default:
        throw std::range_error("Invalid token type");
        break;
    }

    if ( bRes == FALSE || !hToken )
    {
        return Err(ErrorCode::PermissionDenied);
    }

    m_TokenHandle     = pwn::UniqueHandle {hToken};
    m_TokenAccessMask = NewDesiredAccess;
    return Ok(true);
}


Result<PVOID>
Token::QueryInternal(const TOKEN_INFORMATION_CLASS TokenInformationClass, const usize InitialSize)
{
    usize Size             = InitialSize;
    ULONG ReturnLength     = 0;
    NTSTATUS Status        = STATUS_SUCCESS;
    DWORD NewDesiredAccess = (TokenInformationClass == TokenSource) ? TOKEN_QUERY_SOURCE : TOKEN_QUERY;

    if ( Failed(ReOpenTokenWith(NewDesiredAccess)) )
    {
        return Err(ErrorCode::PermissionDenied);
    }

    auto Buffer = ::LocalAlloc(LPTR, Size);
    if ( !Buffer )
    {
        return Err(ErrorCode::AllocationError);
    }

    do
    {
        Status = ::NtQueryInformationToken(m_TokenHandle.get(), TokenInformationClass, Buffer, Size, &ReturnLength);
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


#pragma region Token::Privilege

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


Result<bool>
Token::AddPrivilege(std::wstring_view const& PrivilegeName)
{
    if ( Failed(ReOpenTokenWith(TOKEN_ADJUST_PRIVILEGES)) )
    {
        return Err(ErrorCode::PermissionDenied);
    }

    LUID Luid = {0};

    if ( ::LookupPrivilegeValueW(nullptr, PrivilegeName.data(), &Luid) == false )
    {
        return Err(ErrorCode::ExternalApiCallFailed);
    }

    size_t nBufferSize                 = sizeof(TOKEN_PRIVILEGES) + 1 * sizeof(LUID_AND_ATTRIBUTES);
    auto Buffer                        = std::make_unique<u8[]>(nBufferSize);
    auto NewState                      = reinterpret_cast<PTOKEN_PRIVILEGES>(Buffer.get());
    NewState->PrivilegeCount           = 1;
    NewState->Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    NewState->Privileges[0].Luid       = Luid;

    if ( ::AdjustTokenPrivileges(
             m_TokenHandle.get(),
             FALSE,
             NewState,
             0,
             (PTOKEN_PRIVILEGES) nullptr,
             (PDWORD) nullptr) == FALSE )
    {
        if ( ::GetLastError() == ERROR_NOT_ALL_ASSIGNED )
        {
            return Err(ErrorCode::PartialResult);
        }

        return Err(ErrorCode::ExternalApiCallFailed);
    }

    return Ok(true);
}


Result<bool>
Token::HasPrivilege(std::wstring_view const& PrivilegeName)
{
    if ( Failed(ReOpenTokenWith(TOKEN_ADJUST_PRIVILEGES)) )
    {
        return Err(ErrorCode::PermissionDenied);
    }

    LUID_AND_ATTRIBUTES PrivAttr = {{0}};
    PrivAttr.Attributes          = SE_PRIVILEGE_ENABLED | SE_PRIVILEGE_ENABLED_BY_DEFAULT;

    if ( ::LookupPrivilegeValueW(nullptr, PrivilegeName.data(), &PrivAttr.Luid) == false )
    {
        log::perror(L"LookupPrivilegeValue()");
        return Err(ErrorCode::ExternalApiCallFailed);
    }

    PRIVILEGE_SET PrivSet  = {0};
    PrivSet.PrivilegeCount = 1;
    PrivSet.Privilege[0]   = PrivAttr;
    BOOL bHasPriv          = FALSE;

    if ( ::PrivilegeCheck(m_TokenHandle.get(), &PrivSet, &bHasPriv) == FALSE )
    {
        log::perror(L"PrivilegeCheck()");
        return Err(ErrorCode::ExternalApiCallFailed);
    }

    return Ok(bHasPriv == TRUE);
}

#pragma endregion Token::Privilege

} // namespace pwn::windows
