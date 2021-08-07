#include "rpc.hpp"


extern "C" __declspec(dllexport) void __RPC_FAR* __RPC_USER midl_user_allocate(size_t len)
{
    return new BYTE[len];
}

extern "C" __declspec(dllexport) void __RPC_USER midl_user_free(void __RPC_FAR* ptr)
{
    delete[] ptr;
}

