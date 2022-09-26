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
        ::DuplicateHandle(
            m_ProcessTokenHandle.get(),
            OldCopy.m_ProcessTokenHandle.get(),
            m_ProcessTokenHandle.get(),
            &hDuplicated,
            0,
            false,
            DUPLICATE_SAME_ACCESS
        );

        m_ProcessTokenHandle = pwn::UniqueHandle{hDuplicated};

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


private:
    Result<std::unique_ptr<u8[]>> Query(TOKEN_INFORMATION_CLASS);

    SharedHandle m_ProcessHandle;
    UniqueHandle m_ProcessTokenHandle;
};

} // namespace pwn::windows
