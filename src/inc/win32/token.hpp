#pragma once


#include "common.hpp"
#include "handle.hpp"

namespace pwn::windows
{

class Token
{
public:
    Token() : Token(nullptr)
    {
    }

    Token(SharedHandle ProcessHandle) : m_ProcessHandle(ProcessHandle), m_ProcessTokenHandle()
    {
        if ( Failed(ReOpenTokenWithAccess(TOKEN_ALL_ACCESS)) )
        {
            ReOpenTokenWithAccess(TOKEN_QUERY);
        }
    }

    Token(Token&&) = default;

    ~Token() = default;

    Token&
    operator=(Token&&) = default;

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
