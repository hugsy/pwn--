///
/// @file Example using the Process class
///
///

#include <pwn.hpp>

namespace ctx = pwn::context;

// constexpr PROCESS_INFORMATION_CLASS ProcessDebugAuthInformation =
//     (const PROCESS_INFORMATION_CLASS)0x5A; // 90 -  exists since REDSTONE4

IMPORT_EXTERNAL_FUNCTION(
    L"ntdll.dll",
    NtSetInformationProcess,
    NTSTATUS,
    HANDLE ProcessHandle,
    int ProcessInformationClass,
    PVOID ProcessInformation,
    ULONG ProcessInformationLength);


// IMPORT_EXTERNAL_FUNCTION(
//     L"ntdll.dll",
//     NtQuerySystemEnvironmentValueEx,
//     NTSTATUS,
//     PUNICODE_STRING VariableName,
//     PWCHAR Value,
//     ULONG ValueBufferLength,
//     PULONG RequiredLength);

//
// Require system environment privilege
//
IMPORT_EXTERNAL_FUNCTION(
    L"ntdll.dll",
    NtQuerySystemEnvironmentValueEx,
    NTSTATUS,
    PUNICODE_STRING VariableName,
    LPGUID VendorGuid,
    PVOID Value,
    PULONG ValueLength,
    PULONG Attributes);


IMPORT_EXTERNAL_FUNCTION(
    L"ntdll.dll",
    NtSetSystemEnvironmentValueEx,
    NTSTATUS,
    PUNICODE_STRING VariableName,
    LPGUID VendorGuid,
    PVOID Value,
    ULONG ValueLength,
    ULONG Attributes);

#ifndef VARIABLE_ATTRIBUTE_NON_VOLATILE
#define VARIABLE_ATTRIBUTE_NON_VOLATILE 0x00000001
#endif // VARIABLE_ATTRIBUTE_NON_VOLATILE


auto
wmain(const int argc, const wchar_t** argv) -> int
{
    NTSTATUS Status;

    pwn::Context.set(pwn::log::log_level_t::LOG_DEBUG);

    //
    // Get the current process
    //
    pwn::windows::Process P {};
    if ( Failed(P.AddPrivilege(L"SeSystemEnvironmentPrivilege")) )
    {
        err(L"failed to acquire `SeSystemEnvironmentPrivilege` ");
        return -1;
    }

    ok(L"Successfully acquired `SeSystemEnvironmentPrivilege` ");

    // pwn::globals.set("x64");


    const std::array<u8, 0x20> GuidUnlockId =
        {0x6F, 0x22, 0xEC, 0xEA, 0xA3, 0xC9, 0x7A, 0x47, 0xA8, 0x26, 0xDD, 0xC7, 0x16, 0xCD, 0xC0, 0xE3};
    std::vector<u8> value(0x20);
    ULONG ReturnLength = 0x20;

    auto self = pwn::windows::Process();
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
        pwn::log::ntperror(L"NtQuerySystemEnvironmentValueEx()", Status);
        return -1;
    }

    info(L"Current UnlockId:");
    pwn::utils::hexdump(value);

    /*
    if ( false == pwn::windows::process::add_privilege(L"SeSystemEnvironmentPrivilege") )
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
        pwn::log::ntperror(L"NtSetSystemEnvironmentValueEx()", Status);
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
        pwn::log::ntperror(L"NtQuerySystemEnvironmentValueEx()", Status);
        return -1;
    }

    info(L"New UnlockId:\n");
    pwn::utils::hexdump(value);

    return 0;


    // pwn::utils::pause();

    // auto random_buffer = pwn::utils::random::buffer(0x40);
    // dbg(L"random_buffer=");
    // pwn::utils::hexdump(random_buffer);

    // auto encoded_buffer = Value(pwn::utils::Base64::Encode(random_buffer));
    // dbg(L"b64=\"{}\"", pwn::utils::to_widestring(encoded_buffer));


    std::vector<u8> encoded_buffer;
    if ( argc >= 2 )
    {
        std::wstring arg {argv[1]};
        auto decoded_string = Value(pwn::utils::Base64::Decode(pwn::utils::to_string(arg)));
        encoded_buffer      = decoded_string;
        pwn::utils::hexdump(encoded_buffer);
    }

    // pwn::utils::debugbreak();

    info(L"sending syscall...");
    Status = NtSetInformationProcess(
        self.handle(),
        ProcessDebugAuthInformation,
        encoded_buffer.data(),
        encoded_buffer.size());

    pwn::log::ntperror(L"NtSetInformationProcess()", Status);


    /*

    // dbg(L"started self");
    // {
    //     auto p = pwn::windows::process::Process();
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
    //     auto res = pwn::windows::system::PidOf(L"Notepad.exe");
    //     if ( Success(res) )
    //     {
    //         auto pids = Value(res);
    //         if ( pids.size() > 0 )
    //         {
    //             auto p = pwn::windows::process::Process(pids.front());
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


    // pwn::utils::pause();
    return EXIT_SUCCESS;
    */
}
