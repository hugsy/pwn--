#pragma once


#include "Common.hpp"
#include "Handle.hpp"
#include "Log.hpp"


namespace pwn::Security
{

template<typename T>
concept TokenizableObject = requires(T t) { t.Handle(); };


class Token
{
public:
    enum class Granularity : u8
    {
        Unknown,
        Process,
        Thread,
    };


    ///
    ///@brief Construct a new Token object
    ///
    ///@param hObject A handle to the type of object the token is attached to
    ///@param Type Indicate the object type
    ///
    Token(HANDLE hObject, Granularity Type);


    ///
    ///@brief Construct a new Token object
    ///
    ///
    Token() = default;


    ///
    ///@brief
    ///
    ///@return true
    ///@return false
    ///
    bool
    IsValid() const;


    ///
    ///@brief
    ///
    ///@return Result<bool>
    ///
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
    /// @brief Check if a process has a privilege
    ///
    /// @param PrivilegeName
    /// @return Result<bool> true if the privilege is acquired (false if not).  ErrorCode otherwise
    ///
    Result<bool>
    HasPrivilege(std::wstring_view const& PrivilegeName);

    ///
    /// @brief Query token information.
    ///
    /// @link
    /// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/ne-ntifs-_token_information_class#constants
    ///
    /// @tparam T
    /// @param TokenInformationClass
    /// @return Result<std::unique_ptr<T>>
    ///
    template<class T>
    Result<std::unique_ptr<T>>
    Query(TOKEN_INFORMATION_CLASS TokenInformationClass)
    {
        auto res = QueryInternal(TokenInformationClass, sizeof(T));
        if ( Failed(res) )
        {
            return Error(res);
        }

        auto RawResult = Value(std::move(res));
        std::unique_ptr<T> TypedResult {(T*)RawResult.release()};
        return Ok(std::move(TypedResult));
    }

    ///
    ///@brief
    ///
    ///@tparam TokenInfoClass
    ///@param TokenInformation
    ///@return Result<usize>
    ///
    template<class TokenInfoClass>
    Result<usize>
    Update(TokenInfoClass const& TokenInformation)
    {
        TOKEN_INFORMATION_CLASS TokenInformationClass = 0;
        const DWORD NewDesiredAccess                  = TOKEN_ADJUST_DEFAULT;
        const ULONG TokenInformationLength            = sizeof(TokenInfoClass);

        if constexpr ( std::is_same_v<TokenInfoClass, TOKEN_DEFAULT_DACL> )
        {
            TokenInformationClass = TokenDefaultDacl;
        }

        if constexpr ( std::is_same_v<TokenInfoClass, TOKEN_PRIMARY_GROUP> )
        {
            TokenInformationClass = TokenPrimaryGroup;
        }

        if constexpr ( std::is_same_v<TokenInfoClass, TOKEN_OWNER> )
        {
            TokenInformationClass = TokenOwner;
        }

        if ( Failed(ReOpenTokenWith(NewDesiredAccess)) )
        {
            return Err(Error::PermissionDenied);
        }

        const NTSTATUS Status = ::NtSetInformationToken(
            m_TokenHandle.get(),
            TokenInformationClass,
            (PVOID)TokenInformation,
            TokenInformationLength);
        if ( !NT_SUCCESS(Status) )
        {
            Log::ntperror(L"NtSetInformationToken()", Status);
            return Err(Error::ExternalApiCallFailed);
        }
        return Ok(Status);
    }

    ///
    /// @brief
    ///
    /// @param DesiredAccess
    /// @return Result<bool>
    ///
    Result<bool>
    ReOpenTokenWith(const DWORD DesiredAccess);

private:
    ///
    ///@brief Should not be called directly
    ///
    ///@param TokenInformationClass
    ///@param InitialSize
    ///@return Result<std::unique_ptr<u8[]>>
    ///
    Result<std::unique_ptr<u8[]>>
    QueryInternal(const TOKEN_INFORMATION_CLASS TokenInformationClass, const usize InitialSize);


    ///@brief A handle to the object to which the token is binded
    HANDLE m_hObject {INVALID_HANDLE_VALUE};

    ///@brief The granularity of the token
    Granularity m_Type {Granularity::Unknown};

    ///@brief Unique pointer to the token handle itself
    UniqueHandle m_TokenHandle {nullptr};

    ///@brief The current access mask of the token
    DWORD m_TokenAccessMask {0};
};


} // namespace pwn::Security
