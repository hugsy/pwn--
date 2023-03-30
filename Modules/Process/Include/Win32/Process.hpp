#pragma once

#include <AccCtrl.h>
#include <securitybaseapi.h>
#include <tlhelp32.h>

#include "Common.hpp"
#include "Handle.hpp"
#include "Win32/Token.hpp"

using namespace pwn;

namespace fs = std::filesystem;

namespace pwn::Process
{

class Process;


class Thread;


///
///@brief Describes a set of threads belonging to a process
///
class ThreadGroup
{
public:
    ThreadGroup()
    {
    }

    ThreadGroup(std::shared_ptr<Process> const& _Process) : m_Process {_Process}
    {
    }

    ThreadGroup(ThreadGroup const& Copy)
    {
        m_Process = Copy.m_Process;
    }

    Result<std::vector<u32>>
    List();

    Thread
    at(u32 Tid);

    Thread
    operator[](u32 Tid);

private:
    std::shared_ptr<Process> m_Process = nullptr;
};


///
///@brief Describe a process memory
///
class Memory
{
public:
    Memory() = default;

    Memory(Process* process);

    auto
    Read(uptr const Address, usize Length) -> Result<std::vector<u8>>;

    auto
    Write(uptr const Address, std::vector<u8> data) -> Result<usize>;

    auto
    Memset(uptr const address, const size_t size, const u8 val = 0x00) -> Result<uptr>;

    auto
    Allocate(
        const size_t Size,
        const wchar_t Permission[3]     = L"rwx",
        const uptr ForcedMappingAddress = 0,
        bool wipe                       = true) -> Result<uptr>;

    auto
    Free(const uptr Address) -> bool;


    ///
    ///@brief Query the process virtual memory
    ///
    ///@tparam T
    ///@param MemoryInformationClass
    ///@return Result<std::shared_ptr<T>>
    ///
    template<class T>
    Result<std::shared_ptr<T>>
    Query(const MEMORY_INFORMATION_CLASS MemoryInformationClass, const uptr BaseAddress = nullptr)
    {
        auto res = QueryInternal(MemoryInformationClass, BaseAddress, sizeof(T));
        if ( Failed(res) )
        {
            return Err(Error(res).code);
        }

        const auto p = reinterpret_cast<T*>(Value(res));
        auto deleter = [](T* x)
        {
            ::LocalFree(x);
        };
        return Ok(std::shared_ptr<T>(p, deleter));
    }

    ///
    ///@brief
    ///
    ///@return Result < std::vector < MEMORY_BASIC_INFORMATION>>
    ///
    Result<std::vector<std::shared_ptr<MEMORY_BASIC_INFORMATION>>>
    Regions();


    ///
    ///@brief Search a pattern in memory
    ///
    ///@param Pattern the pattern to look for
    ///@return Result<std::vector<uptr>>
    ///
    Result<std::vector<uptr>>
    Search(std::vector<u8> const& Pattern);


private:
    ///
    /// @brief Should not be called directly
    ///
    /// @param ProcessInformationClass
    ///
    /// @return Result<PVOID>
    ///
    Result<PVOID>
    QueryInternal(const MEMORY_INFORMATION_CLASS, const uptr BaseAddress, const usize);

    SharedHandle m_ProcessHandle {nullptr};

    Process* m_Process {nullptr};
};


///
///@brief Process integrity levels
///
enum class Integrity : int
{
    Unknown,
    Low,
    Medium,
    High,
    System
};


struct HookedLocation
{
    uptr Location {0};
    std::vector<u8> OriginalBytes {};
};


///
///@brief Describes a Windows Process
///
class Process
{
public:
    Process() = default;

    Process(u32, HANDLE = nullptr, bool = false);

    Process(Process const&);

    ~Process();

    Process&
    operator=(Process const& Copy);

    auto
    operator<=>(Process const&) const = default;

    bool
    IsValid();

    ///
    ///@brief Get the process path
    ///
    ///@return fs::path const&
    ///
    fs::path const&
    Path() const;


    ///
    ///@brief Get the process parent id
    ///
    u32 const
    ParentProcessId() const;


    ///
    ///@brief Get the process id
    ///
    ///@return u32 const
    ///
    u32 const
    ProcessId() const;

    ///
    ///@brief
    ///
    ///@return true
    ///@return false
    ///
    bool
    IsRemote() const
    {
        return !m_IsSelf;
    }


    ///
    /// @brief Calculate and store the address of the ProcessEnvironmentBlock
    ///
    /// @return PPEB
    ///
    PPEB
    ProcessEnvironmentBlock();

    ///
    ///@brief Shortcut to `ProcessEnvironmentBlock()`
    ///
    ///@return PPEB
    ///
    PPEB
    Peb()
    {
        return ProcessEnvironmentBlock();
    };

    ///
    ///@brief
    ///
    ///@return SharedHandle const&
    ///
    SharedHandle const&
    Handle() const
    {
        return m_ProcessHandle;
    }

    ///
    ///@brief
    ///
    ///@param os
    ///@param p
    ///@return std::wostream&
    ///
    friend std::wostream&
    operator<<(std::wostream& os, const Process& p)
    {
        os << L"Process(Pid=" << p.ProcessId() << L", Path='" << p.Path() << L"')";
        return os;
    }

    ///
    /// @brief Kill the process
    ///
    /// @return Result<bool>
    ///
    Result<bool>
    Kill();

    ///
    /// @brief Retrieve the process integrity level
    ///
    /// @return Result<Process::Integrity>
    ///
    Result<Integrity>
    IntegrityLevel();

    ///
    /// @brief Query process information
    ///
    /// @param ProcessInformationClass
    /// @return Result<std::shared_ptr<T>>
    ///
    template<class T>
    Result<std::shared_ptr<T>>
    Query(PROCESSINFOCLASS ProcessInformationClass)
    {
        auto res = QueryInternal(ProcessInformationClass, sizeof(T));
        if ( Failed(res) )
        {
            return Err(Error(res).code);
        }

        const auto p = reinterpret_cast<T*>(Value(res));
        auto deleter = [](T* x)
        {
            ::LocalFree(x);
        };
        return Ok(std::shared_ptr<T>(p, deleter));
    }


    ///
    ///@brief Copy code to the process, and execute in a thread
    ///
    ///@param CodePointer
    ///@param CodePointerSize
    ///
    ///@return `Result<uptr>`
    ///
    Result<uptr>
    Execute(uptr const CodePointer, usize const CodePointerSize);


    ///
    /// @brief Try to re-open the current handle access with new one (accumulate)
    ///
    /// @param DesiredAccess The new access privileges to ask
    ///
    /// @return `Result<bool>`
    ///
    Result<bool>
    ReOpenProcessWith(const DWORD DesiredAccess);


    //
    // Submodules
    //
    Memory Memory;
    Security::Token Token;
    ThreadGroup& Threads = m_Threads;

    Result<bool>
    Hook(uptr Location);

    Result<bool>
    Unhook(uptr Location);

    Result<bool>
    InsertCallback(std::function<void(PCONTEXT)> pFunction);

    Result<bool>
    RemoveCallback(std::function<void(PCONTEXT)> pFunction);


    bool
    ExecuteCallbacks();


    // TODO:
    // - modules
    // - inject
    // - hook

    //
    // Static class methods
    //

    ///
    /// @brief Return a Process object of the current process
    ///
    /// @return Result<Process>
    ///
    static Result<Process>
    Current();

    ///
    /// @brief Create a new process
    ///
    /// @param CommandLine
    /// @param ParentPid
    /// @return Result<Process>
    ///
    static Result<Process>
    New(std::wstring_view const& CommandLine, const u32 ParentPid);

    ///
    /// @brief Invoke `ShellExecute` to create a process
    ///
    /// @param lpCommandLine
    /// @param operation
    ///
    /// @return Result<bool>
    ///
    static Result<bool>
    System(_In_ const std::wstring& lpCommandLine, _In_ const std::wstring& operation = L"open");

private:
    ///
    /// @brief Should not be called directly
    ///
    /// @param ProcessInformationClass
    ///
    /// @return Result<PVOID>
    ///
    Result<PVOID>
    QueryInternal(const PROCESSINFOCLASS, const usize);

    u32 m_Pid {0};
    u32 m_Ppid {0};
    bool m_Valid {false};
    fs::path m_Path {};
    Integrity m_IntegrityLevel {Integrity::Unknown};
    SharedHandle m_ProcessHandle {nullptr};
    DWORD m_ProcessHandleAccessMask {0};
    bool m_KillOnClose {false};
    bool m_IsSelf {false};
    bool m_IsWow64 {false};
    PPEB m_Peb {nullptr};
    ThreadGroup m_Threads {};
    std::vector<HookedLocation> m_Hooks {};
    std::vector<std::function<void(PCONTEXT)>> m_HookCallbacks {};
};


///
/// @brief Returns a basic list of processes, in a vector of tuple <Process>
/// TODO: switch to return Result<ProcessGroup> + allow Predicate as argument to filter out stuff
///
/// @return std::vector<Process>
///
PWNAPI Result<std::vector<Process>>
Processes();


class AppContainer
{
public:
    AppContainer(
        std::wstring_view const& container_name,
        std::wstring_view const& executable_path,
        std::vector<WELL_KNOWN_SID_TYPE> const& DesiredCapabilities = {});

    ~AppContainer();

    _Success_(return)
    auto
    AllowFileOrDirectory(_In_ const std::wstring& file_or_directory_name) -> bool;

    _Success_(return)
    auto
    AllowRegistryKey(_In_ const std::wstring& regkey) -> bool;

    _Success_(return)
    auto
    Spawn() -> bool;

    _Success_(return)
    auto
    RestoreAcls() -> bool;

    _Success_(return)
    auto
    Join(_In_ u32 dwTimeout = INFINITE) -> bool;

private:
    auto
    SetNamedObjectAccess(
        const std::wstring& ObjectName,
        const SE_OBJECT_TYPE ObjectType,
        const ACCESS_MODE AccessMode,
        const ACCESS_MASK AccessMask) -> bool;

    std::wstring m_ContainerName;
    std::wstring m_ExecutablePath;
    std::vector<WELL_KNOWN_SID_TYPE> m_Capabilities;
    std::vector<std::tuple<std::wstring, SE_OBJECT_TYPE, PACL>> m_OriginalAcls;
    std::wstring m_SidAsString;
    std::wstring m_FolderPath;

    PSID m_AppContainerSid                       = nullptr;
    STARTUPINFOEX m_StartupInfo                  = {{0}};
    PROCESS_INFORMATION m_ProcessInfo            = {nullptr};
    SECURITY_CAPABILITIES m_SecurityCapabilities = {nullptr};
};

} // namespace pwn::Process


std::wostream&
operator<<(std::wostream& wos, const Process::Integrity i);
