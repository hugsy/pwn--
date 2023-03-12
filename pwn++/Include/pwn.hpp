#pragma once

// clang-format off
#include "pch.hpp"
#include "Formatters.hpp"

#include "Common.hpp"
#include "Architecture.hpp"
#include "Log.hpp"
#include "Utils.hpp"
#include "Handle.hpp"
#include "Context.hpp"

#include "Disassembler.hpp"
#include "Crypto.hpp"

#if defined( PWN_BUILD_FOR_WINDOWS)
#include "Win32/Network.hpp"
#include "Win32/FileSystem.hpp"
#include "Win32/System.hpp"
#include "Win32/PE.hpp"
#include "Win32/Network.hpp"
#include "Win32/Job.hpp"
#include "Win32/Process.hpp"
#include "Win32/Thread.hpp"
#include "Win32/Token.hpp"
#include "Win32/ObjectManager.hpp"
#include "Win32/System.hpp"
#include "Win32/Service.hpp"
#include "Win32/ALPC.hpp"
#include "Win32/RPC.hpp"
#include "API.hpp"
#include "Symbols.hpp"

#include "CTF/Win32/Remote.hpp"
#include "CTF/Win32/Process.hpp"
#elif defined(PWN_BUILD_FOR_WINDOWS)
// TODO
#endif // PWN_BUILD_FOR_WINDOWS
// clang-format on

namespace pwn
{
// clang-format off
///
///@brief
///
constexpr std::wstring_view LibraryName    = L"pwn++";

///
///@brief
///
constexpr std::wstring_view LibraryAuthor  = L"hugsy";

///
///@brief
///
constexpr std::wstring_view LibraryLicense = L"MIT";

///
///@brief
///
constexpr std::wstring_view LibraryBanner = L"pwn++" L" v" L"0.1.3" L" - " L"Standalone";
// clang-format on

constexpr struct
{
    u8 Major;
    u8 Minor;
    u16 Patch;
    std::wstring_view Release;
    std::wstring_view VersionString;
} Version = {
    // clang-format off
    0,
    1,
    3,
    L"Standalone",
    L"0.1.3",
    // clang-format on
};

constexpr struct
{
    std::wstring_view Architecture;
    std::wstring_view System;
} Target {
    // clang-format off
    L"AMD64",
    L"Windows"
    // clang-format on
};

// clang-format off
///
///@brief
///
constexpr std::array<std::wstring_view, 16> Modules;
// clang-format on


} // namespace pwn
