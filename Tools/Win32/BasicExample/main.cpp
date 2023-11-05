///
/// @file Sandbox example file
///
///

#include <pwn>
using namespace pwn;

// constexpr PROCESS_INFORMATION_CLASS ProcessDebugAuthInformation =
//     (const PROCESS_INFORMATION_CLASS)0x5A; // 90 -  exists since REDSTONE4


#ifndef VARIABLE_ATTRIBUTE_NON_VOLATILE
#define VARIABLE_ATTRIBUTE_NON_VOLATILE 0x00000001
#endif // VARIABLE_ATTRIBUTE_NON_VOLATILE


auto
wmain(const int argc, const wchar_t** argv) -> int
{
    NTSTATUS Status;

    Context.Set(Log::LogLevel::Debug);

    //
    // Get the current process and its token
    //
    auto self = Process::Current();
    Security::Token ProcessToken(self.Handle(), Security::Token::Granularity::Process);
    if ( Failed(ProcessToken.AddPrivilege(L"SeSystemEnvironmentPrivilege")) )
    {
        err(L"failed to acquire `SeSystemEnvironmentPrivilege` ");
        return -1;
    }

    ok(L"Successfully acquired `SeSystemEnvironmentPrivilege` ");

    const std::array<u8, 0x20> GuidUnlockId =
        {0x6F, 0x22, 0xEC, 0xEA, 0xA3, 0xC9, 0x7A, 0x47, 0xA8, 0x26, 0xDD, 0xC7, 0x16, 0xCD, 0xC0, 0xE3};
    std::vector<u8> value(0x20);
    ULONG ReturnLength = 0x20;


    // ok(L"using handle={:x}", self.handle());
    // info(
    //     L"pid={}, ppid={}, cmdline='{}' integrity={} is_elevated={}",
    //     self.pid(),
    //     self.ppid(),
    //     self.path().c_str(),
    //     self.integrity(),
    //     self.is_elevated());
    // self.enumerate_privileges();
    // return 0;
    // self.privileges += L"SeSystemEnvironmentPrivilege";

    UNICODE_STRING UnlockIdName;
    ::RtlInitUnicodeString(&UnlockIdName, L"UnlockIDCopy");

    Status = NtQuerySystemEnvironmentValueEx(
        &UnlockIdName,
        (LPGUID)GuidUnlockId.data(),
        value.data(),
        &ReturnLength,
        nullptr);
    if ( Status != 0 )
    {
        Log::ntperror(L"NtQuerySystemEnvironmentValueEx()", Status);
        return -1;
    }

    info(L"Current UnlockId:");
    Utils::Hexdump(value);

    /*
    if ( false == windows::process::add_privilege(L"SeSystemEnvironmentPrivilege") )
    {
        err(L"failed to acquire `SeSystemEnvironmentPrivilege` ");
        return -1;
    }
    */

    u8 b[0x20];
    memset(b, 'A', __countof(b));

    Status = NtSetSystemEnvironmentValueEx(
        &UnlockIdName,
        (LPGUID)GuidUnlockId.data(),
        b,
        ReturnLength,
        VARIABLE_ATTRIBUTE_NON_VOLATILE);
    if ( Status != 0 )
    {
        Log::ntperror(L"NtSetSystemEnvironmentValueEx()", Status);
        return -1;
    }

    ok(L"Successfully called `NtSetSystemEnvironmentValueEx` ");

    Status = NtQuerySystemEnvironmentValueEx(
        &UnlockIdName,
        (LPGUID)GuidUnlockId.data(),
        value.data(),
        &ReturnLength,
        nullptr);
    if ( Status != 0 )
    {
        Log::ntperror(L"NtQuerySystemEnvironmentValueEx()", Status);
        return -1;
    }

    info(L"New UnlockId:\n");
    Utils::Hexdump(value);

    return 0;


    std::vector<u8> encoded_buffer;
    if ( argc >= 2 )
    {
        std::wstring arg {argv[1]};
        auto decoded_string = Value(Utils::Base64::Decode(Utils::StringLib::To<std::string>(arg)));
        encoded_buffer      = decoded_string;
        Utils::Hexdump(encoded_buffer);
    }

    // Utils::DebugBreak();

    info(L"sending syscall...");
    Status = NtSetInformationProcess(
        self.Handle(),
        ProcessDebugAuthInformation,
        encoded_buffer.data(),
        encoded_buffer.size());

    Log::ntperror(L"NtSetInformationProcess()", Status);


    /*

    // dbg(L"started self");
    // {
    //     auto p = windows::process::Process();
    //     info(L"pid={}, ppid={}, cmdline='{}' integrity={}", p.pid(), p.ppid(), p.Path().c_str(), p.integrity());

    //     auto res = p.memory().allocate(0x1000);
    //     if ( Success(res) )
    //     {
    //         auto ptr = Value(res);
    //     }
    //     else
    //     {
    //         err(L"allocate() failed with GLE={:x}", ::GetLastError());
    //     }
    // }
    // dbg(L"ended self");


    // dbg(L"started notepad");
    // {
    //     auto res = windows::system::PidOf(L"Notepad.exe");
    //     if ( Success(res) )
    //     {
    //         auto pids = Value(res);
    //         if ( pids.size() > 0 )
    //         {
    //             auto p = windows::process::Process(pids.front());
    //             info(L"pid={}, ppid={}, cmdline='{}' integrity={}", p.pid(), p.ppid(), p.Path().c_str(),
    //             p.integrity()); info(L"TEB={:#x}, PEB={:#x}", (PVOID)p.teb(), (PVOID)p.peb());
    //         }
    //     }
    //     else
    //     {
    //         auto const& e = Error(res);
    //         err(L"PidOf('notepad') failed with GLE={:x}", e.number);
    //     }
    // }
    // dbg(L"ended notepad");


    // Utils::Pause();
    return EXIT_SUCCESS;
    */
}
