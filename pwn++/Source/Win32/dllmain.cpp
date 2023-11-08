#include <pwn>
using namespace pwn;

#if PWN_BUILD_SHARED_LIB
#ifdef PWN_BUILD_FOR_WINDOWS
void
OnAttachRoutine()
{
    //
    // Initialize the RNG
    //
    utils::random::seed();
}


void
OnDetachRoutine()
{
}


BOOL APIENTRY
DllMain(_In_ HMODULE hModule, _In_ DWORD ul_reason_for_call, _In_ LPVOID lpReserved)
{
    UnreferencedParameter(hModule);
    UnreferencedParameter(lpReserved);

    switch ( ul_reason_for_call )
    {
    case DLL_PROCESS_ATTACH:
        OnAttachRoutine();
        break;

    case DLL_PROCESS_DETACH:
        OnDetachRoutine();
        break;

    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
        break;
    }
    return true;
}

#endif // PWN_BUILD_FOR_WINDOWS

#endif // PWN_BUILD_SHARED_LIB
