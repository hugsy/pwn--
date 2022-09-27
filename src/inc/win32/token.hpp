#pragma once


#include "common.hpp"
#include "handle.hpp"
#include "log.hpp"

namespace pwn::windows
{

class Token
{
public:
    Token() : m_ProcessHandle(nullptr), m_ProcessTokenHandle(nullptr), m_ProcessTokenAccessMask(0)
    {
    }

    Token(SharedHandle ProcessHandle) :
        m_ProcessHandle(ProcessHandle),
        m_ProcessTokenHandle(),
        m_ProcessTokenAccessMask(0)
    {
        if ( Failed(ReOpenTokenWith(TOKEN_ALL_ACCESS)) )
        {
            ReOpenTokenWith(TOKEN_QUERY);
        }
    }

    Token&
    operator=(Token const& OldCopy)
    {
        m_ProcessHandle          = OldCopy.m_ProcessHandle;
        m_ProcessTokenAccessMask = 0;

        HANDLE hDuplicated;
        if ( FALSE == ::DuplicateHandle(
                          m_ProcessHandle->get(),
                          OldCopy.m_ProcessTokenHandle.get(),
                          m_ProcessHandle->get(),
                          &hDuplicated,
                          0,
                          false,
                          DUPLICATE_SAME_ACCESS) )
        {
            log::perror(L"Token::operator=::DuplicateHandle()");
        }
        else
        {
            m_ProcessTokenAccessMask = OldCopy.m_ProcessTokenAccessMask;
            m_ProcessTokenHandle     = pwn::UniqueHandle {hDuplicated};
        }

        return *this;
    }

    Token&
    operator=(Token&&) = default;

    bool
    IsValid() const;

    Result<bool>
    IsElevated();

    Result<bool>
    EnumeratePrivileges();

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

private:
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

    SharedHandle m_ProcessHandle;
    UniqueHandle m_ProcessTokenHandle;
    DWORD m_ProcessTokenAccessMask;
};

} // namespace pwn::windows
