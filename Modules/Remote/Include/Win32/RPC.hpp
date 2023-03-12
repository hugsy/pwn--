#pragma once

#include <Rpc.h>

#include "API.hpp"
#include "Common.hpp"

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
