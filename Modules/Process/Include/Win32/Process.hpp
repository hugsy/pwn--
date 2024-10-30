#pragma once

#include <AccCtrl.h>
#include <securitybaseapi.h>
#include <tlhelp32.h>

#include <ranges>

#include "Common.hpp"
#include "Handle.hpp"
#include "Win32/System.hpp"
#include "Win32/Thread.hpp"
#include "Win32/Token.hpp"

using namespace pwn;

namespace pwn::Process
{

// class Memory;
class Process;
class Thread;
// class ThreadGroup;


///
///@brief Describe a process memory
///
class Memory
{
public:
    ///
    ///@brief Default constructor
    ///
    Memory() = default;


    ///
    ///@brief Construct a new Memory object for a given process
    ///
    ///@param _Process
    ///
    Memory(Process& _Process);


    ///
    ///@brief Read some bytes from memory
    ///
    ///@param Address
    ///@param Length
    ///@return Result<std::vector<u8>>
    ///
    auto
    Read(uptr const Address, usize Length) -> Result<std::vector<u8>>;


    ///
    ///@brief Write some bytes to memory
    ///
    ///@param Address
    ///@param data
    ///@return Result<usize>
    ///
    auto
    Write(uptr const Address, std::vector<u8> data) -> Result<usize>;


    ///
    ///@brief Fill the memory with specific byte
    ///
    ///@param address
    ///@param size
    ///@param val
    ///@return Result<usize>
    ///
    auto
    Memset(uptr const address, const usize size, const u8 val = 0x00) -> Result<usize>;


    ///
    ///@brief Allocate memory in the local/remote process
    ///
    ///@param Size
    ///@param Permission
    ///@param ForcedMappingAddress
    ///@param wipe
    ///@return Result<uptr>
    ///
    auto
    Allocate(
        const size_t Size,
        const wchar_t Permission[3]     = L"rwx",
        const uptr ForcedMappingAddress = 0,
        bool wipe                       = true) -> Result<uptr>;


    Result<bool>
    Free(const uptr Address);


    ///
    ///@brief Query the process virtual memory
    ///
    ///@tparam T
    ///@param MemoryInformationClass
    ///@return Result<std::shared_ptr<T>>
    ///
    template<class T>
    Result<std::unique_ptr<T>>
    Query(const MEMORY_INFORMATION_CLASS MemoryInformationClass, const uptr BaseAddress = nullptr)
    {
        auto res = QueryInternal(MemoryInformationClass, BaseAddress, sizeof(T));
        if ( Failed(res) )
        {
            return Error(res);
        }

        auto RawResult = Value(std::move(res));
        std::unique_ptr<T> TypedResult {(T*)RawResult.release()};
        return Ok(std::move(TypedResult));
    }

    ///
    ///@brief
    ///
    ///@return Result < std::vector < MEMORY_BASIC_INFORMATION>>
    ///
    Result<std::vector<std::unique_ptr<MEMORY_BASIC_INFORMATION>>>
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
    /// @return Result<std::unique_ptr<u8[]>>
    ///
    Result<std::unique_ptr<u8[]>>
    QueryInternal(const MEMORY_INFORMATION_CLASS, const uptr BaseAddress, const usize);


private:
    Process& m_Process;
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


///
///@brief
///
class HookedLocation
{
public:
    uptr Location {0};
    std::vector<u8> OriginalBytes {};
};


///
///@brief Describes a Windows Process
///
class Process
{
public:
    ///
    ///@brief Construct a new default Process object
    ///
    Process() = default;


    ///
    ///@brief Construct a Process object from its PID. Collects a minimum amount of info about the process itself to
    /// speed things up, the other information will be collected lazily.
    ///
    ///@param Pid
    ///
    ///@throws std::runtime_error on initialization failure
    ///
    Process(u32 Pid);


    ///
    ///@brief Same as with a pid, but with a handle
    ///
    ///@param hProcess
    ///
    Process(HANDLE&& hProcess);


    ///
    ///@brief Define "Spaceship operator" when sorting processes
    ///
    auto
    operator<=>(Process const&) const = default;


    ///
    ///@brief `Process` is `Indexable`
    ///
    ///@return u32
    ///
    u32
    Id() const
    {
        return m_ProcessId;
    }


    ///
    ///@brief Get the process id
    ///
    ///@return u32 const
    ///
    u32 const
    ProcessId() const
    {
        return Id();
    }


    ///
    ///@brief Get the process parent id
    ///
    u32 const
    ParentProcessId() const
    {
        return m_ParentProcessId;
    }


    Result<pwn::Process::Process>
    Parent()
    {
        if ( m_ParentProcessId <= 0 )
        {
            return Err(ErrorCode::InvalidProcess);
        }

        return Ok(std::move(Process(m_ParentProcessId)));
    }

    ///
    ///@brief Get the process path
    ///
    ///@return fs::path const&
    ///
    std::wstring const&
    Path() const
    {
        return m_NativePath;
    }


    ///
    ///@brief
    ///
    ///@return true
    ///@return false
    ///
    bool
    IsRemote() const
    {
        return ::GetCurrentProcessId() != ProcessId();
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
    ///@brief Access to the process handle
    ///
    ///@return
    ///
    auto const
    Handle() const
    {
        return m_ProcessHandle.get();
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
    /// @return Result<std::unique_ptr<T>>
    ///
    template<class T>
    Result<std::unique_ptr<T>>
    Query(PROCESSINFOCLASS ProcessInformationClass)
    {
        auto res = QueryInternal(ProcessInformationClass, sizeof(T));
        if ( Failed(res) )
        {
            return Error(res);
        }

        auto RawResult = Value(std::move(res));
        std::unique_ptr<T> TypedResult {(T*)RawResult.release()};
        return Ok(std::move(TypedResult));
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


    ///
    /// @brief Enumerate the process modules
    ///
    /// @return Result<std::vector<LDR_DATA_TABLE_ENTRY>>
    ///
    Result<std::vector<LDR_DATA_TABLE_ENTRY>>
    Modules();


    // TODO (finish):
    // - inject
    // - hook

    //
    // Static class methods
    //


    ///
    /// @brief Create a new process
    ///
    /// @param CommandLine
    /// @param ParentPid
    /// @return Result<Process>
    ///
    // static Result<Process>
    // New(std::wstring_view const& CommandLine, const u32 ParentPid);

    ///
    /// @brief Invoke `ShellExecute` to create a process
    ///
    /// @param lpCommandLine
    /// @param operation
    ///
    /// @return Result<bool>
    ///
    // static Result<bool>
    // System(_In_ const std::wstring& lpCommandLine, _In_ const std::wstring& operation = L"open");

    // Memory& Memory = m_Memory;

    // ProcessToken& Token = m_Token;

    ///
    ///@brief Returns a vector of the ThreadIDs of all threads in the current process
    ///
    ///@return std::vector<u32>
    ///
    std::vector<u32>
    Threads() const;

    ///
    ///@brief
    ///
    ///@param tid
    ///@return Result<pwn::Process::Thread>
    ///
    Result<pwn::Process::Thread>
    Thread(usize tid) const;


private: // Methods
    ///
    /// @brief Wrapper for NtQueryInformationProcess()
    /// Should not be called directly
    ///
    /// @param ProcessInformationClass
    ///
    /// @return Result<std::unique_ptr<u8[]>>
    ///
    Result<std::unique_ptr<u8[]>>
    QueryInternal(const PROCESSINFOCLASS, const usize);

    Result<std::vector<LDR_DATA_TABLE_ENTRY>>
    EnumerateLocalModules();

    Result<std::vector<LDR_DATA_TABLE_ENTRY>>
    EnumerateRemoteModules();

private: // Members
    u32 m_ProcessId {0};
    u32 m_ParentProcessId {0};
    std::wstring m_NativePath {};
    Integrity m_IntegrityLevel {Integrity::Unknown};
    UniqueHandle m_ProcessHandle {nullptr};
    DWORD m_ProcessHandleAccessMask {0};
    PPEB m_Peb {nullptr};
    bool m_IsWow64 {false};
    std::vector<HookedLocation> m_Hooks {};
    std::vector<std::function<void(PCONTEXT)>> m_HookCallbacks {};
};

///
/// @brief Return a Process object of the current process
///
/// @return Result<Process>
///
/// @throws on failure
///
pwn::Process::Process
Current();

using ProcessGroup = IndexedVector<Process>;

///
/// @brief Returns a basic list of processes, in a vector of tuple <Process>
/// TODO: switch to return Result<ProcessGroup> + allow Predicate as argument to filter out stuff
///
/// @return Result<std::vector<u32>>
///
Result<std::vector<u32>>
Processes();


class AppContainer
{
public:
    AppContainer(
        std::wstring_view const& container_name,
        std::wstring_view const& executable_path,
        std::vector<WELL_KNOWN_SID_TYPE> const& DesiredCapabilities = {});

    ~AppContainer();

    auto
    AllowFileOrDirectory(_In_ const std::wstring& file_or_directory_name) -> bool;

    auto
    AllowRegistryKey(_In_ const std::wstring& regkey) -> bool;

    auto
    Spawn() -> bool;

    auto
    RestoreAcls() -> bool;

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
