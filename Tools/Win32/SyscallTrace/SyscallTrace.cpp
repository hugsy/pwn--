///
/// @file SyscallTrace.cpp
///
/// @author @hugsy
///
/// @brief Basic syscall tracer based on ProcessInstrumentationCallback
///
/// @ref Alex Ionescu - Hooking Nirvana (https://github.com/ionescu007/HookingNirvana)
///

#include <pwn>
using namespace pwn;

EXTERN_C_START
PTEB
NtCurrentTeb();

void
Trampoline();
EXTERN_C_END

static bool bKeepActive        = false;
static bool bAlreadyInCallback = false;

EXTERN_C
void
InstrumentationHook(PCONTEXT Context)
{
    if ( bAlreadyInCallback == false )
    {
        bAlreadyInCallback     = true;
        const PTEB Teb         = reinterpret_cast<PTEB>(::NtCurrentTeb());
        const bool bIsDisabled = (Teb->InstrumentationCallbackDisabled == 1);
        Context->Rip           = *((uptr*)(Teb->InstrumentationCallbackPreviousPc));
        Context->Rsp           = *((uptr*)(Teb->InstrumentationCallbackPreviousSp));
        Context->Rcx           = Context->R10;

        if ( bIsDisabled == false )
        {
            //
            // Disable instrumentation to avoid endless recursive loop
            //
            Teb->InstrumentationCallbackDisabled = 1;

            Symbols::ResolveFromAddress(Context->Rax);


            //
            // On 2nd call, restore flag to allow further processing
            //
            Teb->InstrumentationCallbackDisabled = 0;
        }
    }

    ::RtlRestoreContext(Context, nullptr);
    bAlreadyInCallback = false;
}


bool
ConsoleCtrlHandler(DWORD signum)
{
    switch ( signum )
    {
    case CTRL_C_EVENT:
        dbg(L"Stopping...");
        bKeepActive = false;
        break;

    default:
        break;
    }

    return true;
}


auto
wmain(const int argc, const wchar_t** argv) -> int
{
    Context.LogLevel.Set(Log::LogLevel::Debug);

    const auto target_process = (argc >= 2) ? std::wstring(argv[1]) : std::wstring(L"notepad.exe");

    dbg(L"Looking for '{}'...", target_process);

    //
    // Look for the process
    //
    u32 pid = -1;
    {
        auto res = System::System::PidOf(target_process);
        if ( Failed(res) )
        {
            err(L"Failed to find PID of '{}'", target_process);
            return EXIT_FAILURE;
        }

        auto const& pids = Value(res);
        if ( pids.size() == 0 )
        {
            err(L"No process named '{}' found", target_process);
            return EXIT_FAILURE;
        }
        pid = pids.front();
        info(L"Found '{}' with pid={}", target_process, pid);
    }

    pid = ::GetCurrentProcessId();


    Process Process {pid};
    if ( !Process.IsValid() )
    {
        return EXIT_FAILURE;
    }

    //
    // NtSetInformationProcess() requires to have PROCESS_SET_INFORMATION
    //
    if ( Failed(Process.ReOpenProcessWith(PROCESS_SET_INFORMATION)) )
    {
        return EXIT_FAILURE;
    }

    const pwn::SharedHandle hProcess = Process.Handle();
    ok(L"Got handle with PROCESS_SET_INFORMATION to {} -> {:p}", target_process, hProcess->get());

    //
    // Install the instrumentation callback
    //
    dbg(L"Trying to install the instrumentation callback...");
    {
        PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION Callback {
            .Version  = 0,
            .Reserved = 0,
            .Callback = Trampoline,
        };

        NTSTATUS Status = Resolver::ntdll::NtSetInformationProcess(
            hProcess->get(),
            ProcessInstrumentationCallback,
            &Callback,
            sizeof(Callback));

        if ( !NT_SUCCESS(Status) )
        {
            Log::ntperror(L"NtSetInformationProcess()", Status);
            return EXIT_FAILURE;
        }

        ok(L"Callback installed!");
    }

    //
    // Wait for Ctrl-C or target process to finish
    //
    if ( ::SetConsoleCtrlHandler((PHANDLER_ROUTINE)ConsoleCtrlHandler, true) == FALSE )
    {
        Log::perror(L"SetConsoleCtrlHandler()");
        return EXIT_FAILURE;
    }

    bKeepActive = true;

    return ::WaitForSingleObject(hProcess->get(), INFINITE) == WAIT_OBJECT_0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
