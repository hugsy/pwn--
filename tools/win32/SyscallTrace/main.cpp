///
/// @file SyscallTrace.cpp
///
/// @author hugsy (hugsy [AT] blah [DOT] cat)
///
/// @brief Basic syscall tracer based on ProcessInstrumentationCallback
///
/// @ref Alex Ionescu - Hooking Nirvana (https://github.com/ionescu007/HookingNirvana)
///

#include <pwn.hpp>

#pragma comment(lib, "Dbghelp.lib")
#include <Dbghelp.h>

#ifndef ProcessInstrumentationCallback
#define ProcessInstrumentationCallback ((PROCESS_INFORMATION_CLASS)40)
#endif // ProcessInstrumentationCallback

typedef struct _PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION
{
    ULONG Version;
    ULONG Reserved;
    PVOID Callback;
} PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION, *PPROCESS_INSTRUMENTATION_CALLBACK_INFORMATION;

extern "C" PTEB
NtCurrentTeb();

IMPORT_EXTERNAL_FUNCTION(
    L"ntdll.dll",
    NtSetInformationProcess,
    NTSTATUS,
    HANDLE ProcessHandle,
    PROCESS_INFORMATION_CLASS ProcessInformationClass,
    PVOID ProcessInformation,
    ULONG ProcessInformationLength);

bool
InstallInstrumentationCallback(const HANDLE hProcess, const PVOID CallbackRoutine)
{
    PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION Callback = {0};
    Callback.Version                                      = 0;
    Callback.Reserved                                     = 0;
    Callback.Callback                                     = CallbackRoutine;

    return NT_SUCCESS(NtSetInformationProcess(hProcess, ProcessInstrumentationCallback, &Callback, sizeof(Callback)));
}

static bool bKeepActive            = false;
static bool bHasInitializedSymbols = false;

void
InstrumentationHook(PCONTEXT Context)
{
    //
    // +0x2d0 InstrumentationCallbackSp : Uint8B
    // +0x2d8 InstrumentationCallbackPreviousPc : Uint8B
    // +0x2e0 InstrumentationCallbackPreviousSp : Uint8B
    // +0x2ec InstrumentationCallbackDisabled : UChar
    //
    PBYTE teb        = reinterpret_cast<PBYTE>(::NtCurrentTeb());
    bool is_disabled = (teb[0x2ec] == 1);
    Context->Rip     = *((uptr*)(teb + 0x02D8));
    Context->Rsp     = *((uptr*)(teb + 0x02E0));
    Context->Rcx     = Context->R10;


    if ( is_disabled == false )
    {
        //
        // Disable instrumentation to avoid endless recursive loop
        //
        teb[0x2ec] = 1;
    }
    else
    {
        //
        // On 2nd call, restore flag to allow further processing
        //
        teb[0x2ec] = 0;
    }

    ::RtlRestoreContext(Context, nullptr);
}

auto
wmain(const int argc, const wchar_t** argv) -> int
{
    pwn::Context.log_level = pwn::log::log_level_t::LOG_DEBUG;

    const auto target_process = (argc >= 2) ? std::wstring(argv[1]) : std::wstring(L"notepad.exe");

    dbg(L"targetting {}", target_process);

    //
    // Look for the process
    //
    // u32 pid = -1;
    // {
    //     auto res = pwn::windows::system::PidOf(target_process);
    //     if ( !Success(res) )
    //     {
    //         err(L"failed to find PID of '{}'", target_process);
    //         return EXIT_FAILURE;
    //     }

    //     auto const& pids = Value(res);
    //     if ( pids.size() == 0 )
    //     {
    //         err(L"empty set of  PIDs named '{}'", target_process);
    //         return EXIT_FAILURE;
    //     }
    //     pid = pids.front();
    //     info(L"found '{}' with pid={}", target_process, pid);
    // }


    //
    // Install the instrumentation callback
    //
    {
        auto hProcess = pwn::UniqueHandle(::OpenProcess(PROCESS_ALL_ACCESS, false, ::GetCurrentProcessId()));
        if ( hProcess )
        {
            ok(L"got handle to {} -> {:p}", target_process, hProcess.get());

            if ( false == InstallInstrumentationCallback(hProcess.get(), InstrumentationHook) )
            {
                err(L"InstallInstrumentationCallback() failed");
                return EXIT_FAILURE;
            }
            ok(L"installed callback");

            // ::SymSetOptions(SYMOPT_UNDNAME);
            // ::SymInitialize(hProcess.get(), nullptr, true);
            // ok(L"initialized symbols");

            /*
            ::SetConsoleCtrlHandler(
                (PHANDLER_ROUTINE)[&hProcess](DWORD signum)->bool {
                    switch ( signum )
                    {
                    case CTRL_C_EVENT:
                        dbg(L"Stopping...\n");
                        bKeepActive = false;
                        break;

                    default:
                        break;
                    }

                    return true;
                },
                true);
            */

            bKeepActive = true;

            ::WaitForSingleObject(hProcess.get(), INFINITE);
        }
    }

    return EXIT_SUCCESS;
}
