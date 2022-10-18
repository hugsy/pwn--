
#include "pwn.hpp"

namespace utils = pwn::utils::random;


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
        auto res = pwn::backdoor::start();
        if ( Failed(res) )
        {
            return;
        }
    }
#endif // PWN_INCLUDE_BACKDOOR
}


void
OnDetachRoutine()
{
#ifdef PWN_INCLUDE_BACKDOOR
    pwn::backdoor::stop();
#endif // PWN_INCLUDE_BACKDOOR
}


BOOL APIENTRY
DllMain(_In_ HMODULE hModule, _In_ DWORD ul_reason_for_call, _In_ LPVOID lpReserved)
{
    UNREFERENCED_PARAMETER(hModule);
    UNREFERENCED_PARAMETER(lpReserved);

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
    return TRUE;
}
