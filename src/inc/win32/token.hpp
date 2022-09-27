#pragma once


#include "common.hpp"
#include "handle.hpp"

namespace pwn::windows
{

class Token
{
public:
    Token() : m_ProcessHandle(nullptr), m_ProcessTokenHandle(nullptr)
    {
    }

    Token(SharedHandle ProcessHandle) : m_ProcessHandle(ProcessHandle), m_ProcessTokenHandle()
    {
        if ( Failed(ReOpenTokenWithAccess(TOKEN_ALL_ACCESS)) )
        {
            ReOpenTokenWithAccess(TOKEN_QUERY);
        }
    }

    Token&
    operator=(Token const& OldCopy)
    {
        m_ProcessHandle = OldCopy.m_ProcessHandle;

        HANDLE hDuplicated;
        if ( TRUE == ::DuplicateHandle(
                         m_ProcessHandle->get(),
                         OldCopy.m_ProcessTokenHandle.get(),
                         m_ProcessHandle->get(),
                         &hDuplicated,
                         0,
                         false,
                         DUPLICATE_SAME_ACCESS) )
        {
            m_ProcessTokenHandle = pwn::UniqueHandle {hDuplicated};
        }


        return *this;
    }

    Token&
    operator=(Token&&) = default;

    bool
    IsValid() const;

    Result<bool>
    ReOpenTokenWithAccess(const DWORD DesiredAccess);

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
};

} // namespace pwn::windows
