#pragma once


#include "Common.hpp"
#include "Handle.hpp"
#include "Log.hpp"

namespace pwn::Security
{

class Token
{
public:
    enum class TokenType : u8
    {
        Unknown,
        Process,
        Thread,
    };


    Token() = default;

    Token(SharedHandle ProcessOrThreadHandle, TokenType Type) :
        m_ProcessOrThreadHandle {ProcessOrThreadHandle},
        m_TokenHandle {nullptr},
        m_TokenAccessMask {0},
        m_Type {Type}
    {
        ReOpenTokenWith(TOKEN_READ | TOKEN_QUERY_SOURCE | TOKEN_DUPLICATE);
    }

    Token&
    operator=(Token const& OldCopy)
    {
        m_ProcessOrThreadHandle = OldCopy.m_ProcessOrThreadHandle;
        m_TokenAccessMask       = 0;

        HANDLE hDuplicated;
        if ( FALSE == ::DuplicateHandle(
                          m_ProcessOrThreadHandle->get(),
                          OldCopy.m_TokenHandle.get(),
                          m_ProcessOrThreadHandle->get(),
                          &hDuplicated,
                          0,
                          false,
                          DUPLICATE_SAME_ACCESS) )
        {
            Log::perror(L"Token::operator=::DuplicateHandle()");
        }
        else
        {
            m_TokenAccessMask = OldCopy.m_TokenAccessMask;
            m_TokenHandle     = UniqueHandle {hDuplicated};
        }

        return *this;
    }

    Token&
    operator=(Token&&) = default;

    bool
    IsValid() const;

    Result<bool>
    IsElevated();

    ///
    /// @brief Enumerate the token privileges
    ///
    /// @return Result<bool>
    ///
    Result<bool>
    EnumeratePrivileges();

    ///
    /// @brief Add a privilege to the process (if possible)
    ///
    /// @param PrivilegeName
    /// @return Result<bool> true if the privilege was added (false, not added). ErrorCode otherwise
    ///
    Result<bool>
    AddPrivilege(std::wstring_view const& PrivilegeName);

    ///
    /// @brief  a privilege to the process (if possible)
    ///
    /// @param PrivilegeName
    /// @return Result<bool> true if the privilege is acquired (false if not).  ErrorCode otherwise
    ///
    Result<bool>
    HasPrivilege(std::wstring_view const& PrivilegeName);

    ///
    /// @brief Query token information
    ///
    /// @tparam T
    /// @param TokenInformationClass
    /// @return Result<std::shared_ptr<T>>
    ///
    template<class T>
    Result<std::shared_ptr<T>>
    Query(TOKEN_INFORMATION_CLASS TokenInformationClass)
    {
        auto res = QueryInternal(TokenInformationClass, sizeof(T));
        if ( Failed(res) )
        {
            return Err(Error(res).code);
        }

        const auto p = reinterpret_cast<T*>(Value(res));
        auto deleter = [](T* x)
        {
            ::LocalFree(x);
        };
        return Ok(std::shared_ptr<T>(p, deleter));
    }

    ///
    ///@brief
    ///
    ///@tparam T
    ///@param TokenInformation
    ///@return Result<usize>
    ///
    template<class T>
    Result<usize>
    Update(T const& TokenInformation)
    {
        TOKEN_INFORMATION_CLASS TokenInformationClass = 0;
        const DWORD NewDesiredAccess                  = TOKEN_ADJUST_DEFAULT;
        const ULONG TokenInformationLength            = sizeof(T);

        if constexpr ( std::is_same_v<T, TOKEN_DEFAULT_DACL> )
        {
            TokenInformationClass = TokenDefaultDacl;
        }

        if constexpr ( std::is_same_v<T, TOKEN_PRIMARY_GROUP> )
        {
            TokenInformationClass = TokenPrimaryGroup;
        }

        if constexpr ( std::is_same_v<T, TOKEN_OWNER> )
        {
            TokenInformationClass = TokenOwner;
        }

        if ( Failed(ReOpenTokenWith(NewDesiredAccess)) )
        {
            return Err(ErrorCode::PermissionDenied);
        }

        const NTSTATUS Status = ::NtSetInformationToken(
            m_TokenHandle.get(),
            TokenInformationClass,
            (PVOID)TokenInformation,
            TokenInformationLength);
        if ( NT_SUCCESS(Status) )
        {
            return Ok(Status);
        }

        Log::ntperror(L"NtSetInformationToken()", Status);
        return Err(ErrorCode::ExternalApiCallFailed);
    }

protected:
    ///
    /// @brief
    ///
    /// @param DesiredAccess
    /// @return Result<bool>
    ///
    Result<bool>
    ReOpenTokenWith(const DWORD DesiredAccess);

    ///
    /// @brief Should not be called directly
    ///
    /// @param ThreadInformationClass
    ///
    /// @return Result<PVOID>
    ///
    Result<PVOID>
    QueryInternal(const TOKEN_INFORMATION_CLASS, const usize);

    SharedHandle m_ProcessOrThreadHandle = nullptr;
    UniqueHandle m_TokenHandle           = nullptr;
    DWORD m_TokenAccessMask              = 0;
    TokenType m_Type                     = TokenType::Unknown;
};


} // namespace Security
