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
Token::IsElevated()
{
    TOKEN_ELEVATION TokenInfo = {0};
    DWORD dwReturnLength      = 0;

    if ( ::GetTokenInformation(
             m_ProcessTokenHandle.get(),
             TokenElevation,
             &TokenInfo,
             sizeof(TOKEN_ELEVATION),
             &dwReturnLength) )
    {
        return Ok(TokenInfo.TokenIsElevated == 1);
    }

    log::perror(L"GetTokenInformation()");
    return Err(ErrorCode::ExternalApiCallFailed);
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


Result<std::shared_ptr<u8[]>>
Token::Query(TOKEN_INFORMATION_CLASS TokenInformationClass)
{
    DWORD ReturnLength;

    //
    // Get size
    //
    ::GetTokenInformation(m_ProcessTokenHandle.get(), TokenInformationClass, nullptr, 0, &ReturnLength);
    if ( ::GetLastError() != ERROR_INSUFFICIENT_BUFFER )
    {
        return Err(ErrorCode::PermissionDenied);
    }

    //
    // Prepare the structure and get the information
    //
    auto TokenInformationBuffer = std::make_shared<u8[]>(ReturnLength);

    auto bRes = ::GetTokenInformation(
        m_ProcessTokenHandle.get(),
        TokenInformationClass,
        TokenInformationBuffer.get(),
        ReturnLength,
        &ReturnLength
    );

    if (bRes == FALSE )
    {
        return Err(ErrorCode::ExternalApiCallFailed);
    }

    return Ok(TokenInformationBuffer);
}


Result<bool>
Token::EnumeratePrivileges()
{
    auto res = Query(TokenPrivileges);
    if(Failed(res))
    {
        return Err(Error(res).code);
    }

    const auto TokenPrivBuffer = Value(res);
    const PTOKEN_PRIVILEGES Privs = reinterpret_cast<PTOKEN_PRIVILEGES>(TokenPrivBuffer.get());
    const DWORD PrivilegeCount = Privs->PrivilegeCount;
    dbg(L"{} privileges", PrivilegeCount);
    for ( u32 i = 0; i < PrivilegeCount; i++ )
    {
        const PLUID_AND_ATTRIBUTES Priv = &(Privs->Privileges[i]);
    }

    return Ok(Privs->PrivilegeCount > 0);
}

} // namespace pwn::windows
