#include "win32/rpc.hpp"

EXTERN_C_START
__declspec(dllexport) void __RPC_FAR* __RPC_USER midl_user_allocate(size_t len)
{
    return new BYTE[len];
}

__declspec(dllexport) void __RPC_USER midl_user_free(void __RPC_FAR* ptr)
{
    delete[] ptr;
}
EXTERN_C_END
