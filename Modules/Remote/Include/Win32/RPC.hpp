#pragma once

#include <Rpc.h>

#include "Common.hpp"
#include "Win32/API.hpp"

///
///
/// Basic helpers for dealing with RPCs
///
///

namespace pwn::Remote::RPC
{
class RpcContext
{
public:
    RpcContext(const std::wstring_view& objuuid, const std::wstring_view& proto);

    ~RpcContext();

private:
    RPC_WSTR m_pszStringBinding;
    RPC_BINDING_HANDLE m_Binding;
};
} // namespace pwn::Remote::RPC
