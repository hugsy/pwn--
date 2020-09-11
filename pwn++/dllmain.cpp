#include "pwn.h"

using namespace pwn::log;
using namespace pwn::utils::random;
using namespace pwn::thread;



void OnAttachRoutine()
{
    g_ConsoleMutex = CreateMutex(NULL, FALSE, NULL);
    pwn::utils::random::seed();

#ifdef PWN_AUTOSTART_BACKDOOR
    pwn::thread::start_backdoor();
#endif // PWN_AUTOSTART_BACKDOOR   
}


void OnDetachRoutine()
{
    if(g_ConsoleMutex)
        ::CloseHandle(g_ConsoleMutex);
}


BOOL
APIENTRY
DllMain( 
    _In_ HMODULE hModule,
    _In_ DWORD  ul_reason_for_call,
    _In_ LPVOID lpReserved
)
{
    UNREFERENCED_PARAMETER(hModule);
    UNREFERENCED_PARAMETER(lpReserved);

    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
    case DLL_THREAD_ATTACH:
        OnAttachRoutine();
        break;

    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        OnDetachRoutine();
        break;
    }
    return TRUE;
}

