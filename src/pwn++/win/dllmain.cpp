#include "pwn.hpp"


using namespace pwn::log;
using namespace pwn::utils::random;

#ifndef PWN_NO_BACKDOOR
using namespace pwn::thread;
using namespace pwn::backdoor;
#endif // !PWN_NO_BACKDOOR


void
OnAttachRoutine()
{
    pwn::utils::random::seed();

#ifndef PWN_NO_BACKDOOR
    {
        pwn::globals.m_backdoor_thread = std::thread::thread(pwn::backdoor::start);

        pwn::globals.m_backdoor_thread.detach();
    }
#endif // !PWN_NO_BACKDOOR
}


void
OnDetachRoutine()
{
    pwn::globals.m_console_mutex.lock();
    {
        //
        // Prevents another thread to lock the mutex while we're exiting
        //

#ifndef PWN_NO_BACKDOOR
        pwn::backdoor::stop();
#endif // !PWN_NO_BACKDOOR

    }

    pwn::globals.m_console_mutex.unlock();
    // todo: tiny race here tho
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
