module;

/**
 * Include non-module, locally only
 */
#include <array>
#include <string_view>

/**
 * Export module `pwn`
 */
export module pwn;

/**
 * Re-export submodules
 */
export import pwn.common;

/**
 * Additional imports
 */
import std;

// // clang-format off
// #include "Common.hpp"
// #include "Architecture.hpp"
// #include "Log.hpp"
// #include "Literals.hpp"
// #include "Formatters.hpp"
// #include "Utils.hpp"
// #include "Handle.hpp"
// #include "Context.hpp"

// #include "Crypto.hpp"

// #ifdef PWN_INCLUDE_DISASSEMBLER
// #include "Disassembler.hpp"
// #endif // PWN_INCLUDE_DISASSEMBLER

// #if defined(PWN_BUILD_FOR_WINDOWS)
// #include "Win32/Network.hpp"
// #include "Win32/FileSystem.hpp"
// #include "Win32/System.hpp"
// #include "Win32/PE.hpp"
// #include "Win32/Network.hpp"
// #include "Win32/Job.hpp"
// #include "Win32/Process.hpp"
// #include "Win32/Thread.hpp"
// #include "Win32/Token.hpp"
// #include "Win32/ObjectManager.hpp"
// #include "Win32/System.hpp"
// #include "Win32/Service.hpp"
// #include "Win32/ALPC.hpp"
// #include "Win32/RPC.hpp"
// #include "Win32/API.hpp"
// #include "Win32/Symbols.hpp"
// #include "CTF/Win32/Remote.hpp"
// #include "CTF/Win32/Process.hpp"

// #elif defined(PWN_BUILD_FOR_LINUX)

// #include "CTF/Linux/Remote.hpp"
// #include "CTF/Linux/Process.hpp"

// #else

// #error "Unsupported OS"

// #endif // PWN_BUILD_FOR_WINDOWS
// clang-format on

namespace pwn
{
// clang-format off
///
///@brief
///
export constexpr std::string_view LibraryName    = "pwn++";

///
///@brief
///
export constexpr std::string_view LibraryAuthor  = "hugsy";

///
///@brief
///
export constexpr std::string_view LibraryLicense = "MIT";

///
///@brief
///
export constexpr std::string_view LibraryBanner = "pwn++" " v" "0.1.3" " - " "Standalone";
// clang-format on

///
///@brief pwn++ version information
///
constexpr struct VersionType
{
    ///
    ///@brief pwn++ major version
    ///
    const u8 Major;

    ///
    ///@brief pwn++ minor version
    ///
    const u8 Minor;

    ///
    ///@brief pwn++ patch information
    ///
    const u16 Patch;

    ///
    ///@brief pwn++ release information
    ///
    const std::string_view Release;

    ///
    ///@brief pwn++ complete version information as wstring
    ///
    const std::string_view VersionString;
} Version = {
    // clang-format off
    0,
    1,
    3,
    "Standalone",
    "0.1.3",
    // clang-format on
};

///
///@brief
///
constexpr struct HostInfo
{
    ///
    ///@brief The host architecture pwn++ was built against
    ///
    const std::string_view Architecture;

    ///
    ///@brief The host OS pwn++ was built against
    ///
    const std::string_view System;
} Host {
    // clang-format off
    "AMD64",
    "Windows"
    // clang-format on
};
// clang-format off

///
///@brief A list of all modules built with pwn++
///
export constexpr std::array<std::string_view, 1> ModuleNames = {"Common",};
// clang-format on

} // namespace pwn
