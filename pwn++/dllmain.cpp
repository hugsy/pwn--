#include "pwn.h"

using namespace pwn::log;
using namespace pwn::backdoor;
using namespace pwn::utils::random;
using namespace pwn::thread;


void
OnAttachRoutine()
{
    pwn::globals.m_console_mutex = ::CreateMutex(nullptr, FALSE, nullptr);
    pwn::utils::random::seed();

#ifndef PWN_NO_BACKDOOR
    {
        pwn::globals.m_backdoor_thread = std::thread::thread(pwn::backdoor::start);

        pwn::globals.m_backdoor_thread.detach();
    }
#endif // PWN_NO_BACKDOOR
}


void
OnDetachRoutine()
{
    if (pwn::globals.m_console_mutex != INVALID_HANDLE_VALUE)
    {
        ::CloseHandle(pwn::globals.m_console_mutex);
    }

#ifndef PWN_NO_BACKDOOR
    pwn::backdoor::stop();
#endif // PWN_NO_BACKDOOR
}


BOOL APIENTRY
DllMain(_In_ HMODULE hModule, _In_ DWORD ul_reason_for_call, _In_ LPVOID lpReserved)
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
