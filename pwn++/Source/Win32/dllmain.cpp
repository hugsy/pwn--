#include <pwn>

using namespace pwn;

void
OnAttachRoutine()
{
    //
    // Initialize the RNG
    //
    Utils::Random::Seed();
}


void
OnDetachRoutine()
{
}


BOOL APIENTRY
DllMain(_In_ HMODULE hModule, _In_ DWORD ul_reason_for_call, _In_ LPVOID lpReserved)
{
    UnusedParameter(hModule);
    UnusedParameter(lpReserved);

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
