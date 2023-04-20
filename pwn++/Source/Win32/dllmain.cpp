#include "pwn.hpp"
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

#ifdef PWN_INCLUDE_BACKDOOR
    //
    // Start the backdoor thread
    //
    {
        auto res = Backdoor::start();
        if ( Failed(res) )
        {
            err(L"Backdoor initialization failed");
        }
    }
#endif // PWN_INCLUDE_BACKDOOR
}


void
OnDetachRoutine()
{
#ifdef PWN_INCLUDE_BACKDOOR
    pwn::backdoor::Stop();
#endif // PWN_INCLUDE_BACKDOOR
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
