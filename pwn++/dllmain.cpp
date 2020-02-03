#include <windows.h>


namespace pwn::globals
{
    extern HANDLE g_ConsoleMutex;
}


void OnAttachRoutine()
{
    pwn::globals::g_ConsoleMutex = CreateMutex(NULL, FALSE, NULL);
}


void OnDetachRoutine()
{
    CloseHandle(pwn::globals::g_ConsoleMutex);
}


BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
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

