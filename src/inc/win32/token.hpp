#pragma once


#include "common.hpp"
#include "handle.hpp"
#include "log.hpp"

namespace pwn::windows
{

class Token
{
public:
    Token() = default;

    Token(SharedHandle ProcessOrThread, bool IsProcess) :
        m_ProcessOrThreadHandle {ProcessHandle},
        m_TokenHandle {nullptr},
        m_TokenAccessMask {0},
        m_IsProcess {IsProcess}
    {
        if ( Failed(ReOpenTokenWith(TOKEN_ALL_ACCESS)) )
        {
            ReOpenTokenWith(TOKEN_QUERY);
        }
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
            log::perror(L"Token::operator=::DuplicateHandle()");
        }
        else
        {
            m_TokenAccessMask = OldCopy.m_TokenAccessMask;
            m_TokenHandle     = pwn::UniqueHandle {hDuplicated};
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
    bool m_IsProcess                     = false;
};


class ProcessToken : public Token
{
public:
    ProcessToken() : Token()
    {
    }


    ProcessToken(SharedHandle ProcessHandle) : Token(ProcessHandle, true)
    {
    }

private:
};


class ThreadToken : public Token
{
public:
    ThreadToken() : Token()
    {
    }


    ThreadToken(SharedHandle ProcessHandle) : Token(ProcessHandle, true)
    {
    }

private:
};


} // namespace pwn::windows
