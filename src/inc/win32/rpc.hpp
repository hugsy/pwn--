#pragma once

#include "common.hpp"
#include "nt.hpp"


/*++
*
* Basic helpers for dealing with RPCs
*
--*/

#include <Rpc.h>

#include <stdexcept>

namespace pwn::windowsdows::rpc
{
class RpcContext
{
public:
    RpcContext(_In_ wchar_t* objuuid, _In_ wchar_t* proto)
    {
        do
        {
            auto status = ::RpcStringBindingComposeW(
                reinterpret_cast<RPC_WSTR>(objuuid),
                reinterpret_cast<RPC_WSTR>(proto),
                nullptr,
                nullptr,
                nullptr,
                &m_pszStringBinding);

            if ( status != RPC_S_OK )
            {
                throw std::runtime_error("RpcStringBindingCompose failed\n");
            }

            status = ::RpcBindingFromStringBindingW(m_pszStringBinding, &m_Binding);
            if ( status != RPC_S_OK )
            {
                throw std::runtime_error("RpcBindingFromStringBinding failed\n");
            }

            RPC_SECURITY_QOS qos;
            qos.Version           = 1;
            qos.ImpersonationType = RPC_C_IMP_LEVEL_IMPERSONATE;
            qos.Capabilities      = RPC_C_QOS_CAPABILITIES_DEFAULT;
            qos.IdentityTracking  = RPC_C_QOS_IDENTITY_STATIC;

            status = ::RpcBindingSetAuthInfoExW(
                m_Binding,
                nullptr,
                RPC_C_AUTHN_LEVEL_NONE,
                RPC_C_AUTHN_WINNT,
                nullptr,
                0,
                &qos);
            if ( status == 0 )
            {
                throw std::runtime_error("RpcBindingSetAuthInfoExW failed\n");
            }
        } while ( 0 );
    }


    ~RpcContext()
    {
        if ( m_pszStringBinding != nullptr )
        {
            RpcStringFreeW(&m_pszStringBinding);
        }

        if ( m_Binding != nullptr )
        {
            RpcBindingFree(&m_Binding);
        }
    }

    RPC_WSTR m_pszStringBinding;
    RPC_BINDING_HANDLE m_Binding;
};
} // namespace pwn::windowsdows::rpc
