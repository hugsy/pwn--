#pragma once

#include "architecture.hpp"
#include "common.hpp"


/**
 *
 * Common namespace definition
 *
 */

/// namespace pwn::log
#include "log.hpp"

/// namespace pwn::utils
#include "utils.hpp"

/// namespace pwn::crypto
#include "crypto.hpp"

#ifdef PWN_INCLUDE_ASSEMBLER
/// namespace pwn::assm
#include "asm.hpp"
#endif // PWN_INCLUDE_ASSEMBLER

/// namespace pwn::disassm
#ifdef PWN_INCLUDE_DISASSEMBLER
#include "disasm.hpp"
#endif // PWN_INCLUDE_DISASSEMBLER


#pragma region pwn::windows
#ifdef PWN_BUILD_FOR_WINDOWS
namespace pwn
{

///
/// @brief pwn::windows namespace declaration
///
///
namespace windows
{

}

///
/// @brief aliasing pwn::win to pwn::windows
///
///
namespace win = windows;

} // namespace pwn

/// namespace pwn::windows, class System
#include "win32/system.hpp"

/// namespace pwn::windows, class Process
#include "win32/process.hpp"

/// namespace pwn::windows, class Thread
#include "win32/thread.hpp"

/// namespace pwn::windows, class Registry
#include "win32/registry.hpp"

/// namespace pwn::windows::kernel
#include "win32/kernel.hpp"

/// namespace pwn::windows::job
#include "win32/job.hpp"

/// namespace pwn::windows::service
#include "win32/service.hpp"

/// namespace pwn::windows::filesystem
#include "win32/fs.hpp"

/// namespace pwn::windows::alpc
#include "win32/alpc.hpp"

/// namespace pwn::windows::rpc
#include "win32/rpc.hpp"

/// namespace pwn::windows, class ObjectManager
#include "win32/object.hpp"

/// namespace pwn::windows, class Symbols
#include "win32/symbols.hpp"

// namespace pwn::backdoor
#ifdef PWN_INCLUDE_BACKDOOR
#include "backdoor.hpp"
#endif


///
/// Aliasing pwn::ctf to the corresponding OS the lib was build for
///
namespace pwn
{
namespace windows::ctf
{
}

/// `pwn::ctf` -> `pwn::windows::ctf` for Windows
namespace ctf = win::ctf;
} // namespace pwn

#include "win32/ctf/process.hpp"
#include "win32/ctf/remote.hpp"

#endif
#pragma endregion


#pragma region pwn::linux
#ifdef PWN_BUILD_FOR_LINUX

namespace pwn
{

///
/// @brief pwn::linux namespace declaration
///
///
namespace linux
{

}

///
/// @brief aliasing pwn::lin to pwn::linux
///
///
namespace lin = linux;

} // namespace pwn

// namespace pwn::linux::system
#include "linux/system.hpp"

namespace pwn
{
namespace linux::ctf
{
}

/// `pwn::ctf` -> `pwn::linux::ctf` for Linux
namespace ctf = linux::ctf;
} // namespace pwn

#include "linux/ctf/remote.hpp"
#endif
#pragma endregion


///
/// @brief pwn namespace declaration
///
namespace pwn
{

///
/// @brief Global context definition
///
struct GlobalContext
{
#ifdef PWN_INCLUDE_BACKDOOR
    std::jthread m_backdoor_thread;
    std::vector<std::shared_ptr<pwn::backdoor::ThreadConfig>> m_backdoor_clients;
#endif
    u64 m_seed;
    std::mutex m_ConsoleMutex;
    std::mutex m_ConfigMutex;
    log::LogLevel LogLevel = log::LogLevel::Info;

    Architecture architecture;
    Endianess endianess;
    usize ptrsize;

    GlobalContext();

    void
    set(std::string_view const& type);

    void
    set(std::wstring_view const& type);

    void
    set(Endianess end);

    void
    set(log::LogLevel new_log_level);
};

///
/// @brief The global context information are stored in this global variable
///
extern PWNAPI struct GlobalContext Context;

///
///@brief pwn++ banner string
///
constexpr std::wstring_view Banner = PWN_LIBRARY_NAME L" v" PWN_LIBRARY_VERSION L" - " PWN_LIBRARY_VERSION_RELEASE;

///
///@brief pwn++ version string
///
constexpr std::wstring_view Version = PWN_LIBRARY_VERSION;

///
///@brief pwn++ version info as a tuple, (major, minor)
///
constexpr std::tuple<u16, u16> VersionInfo {PWN_LIBRARY_VERSION_MAJOR, PWN_LIBRARY_VERSION_MINOR};


} // namespace pwn
