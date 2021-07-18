#include "pwn.h"
#include <thread>

using namespace pwn::log;
using namespace pwn::utils::random;
using namespace pwn::thread;

std::thread g_backdoor;

void OnAttachRoutine()
{
    g_ConsoleMutex = CreateMutex(NULL, FALSE, NULL);
    pwn::utils::random::seed();

#ifdef PWN_AUTOSTART_BACKDOOR
    g_backdoor = std::thread(
        pwn::thread::start_backdoor
    );
    g_backdoor.detach();
#endif // PWN_AUTOSTART_BACKDOOR   
}


void OnDetachRoutine()
{
    if (g_ConsoleMutex && g_ConsoleMutex != INVALID_HANDLE_VALUE)
        ::CloseHandle(g_ConsoleMutex);

#ifdef PWN_AUTOSTART_BACKDOOR
    g_backdoor.join();
#endif // PWN_AUTOSTART_BACKDOOR   
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

