#pragma once

#include <functional>
#include <string_view>
#include <tuple>

#include "common.hpp"

/*

interesting locations from link target

- \rpc control\
- \sessions\$x\BaseNamedObjects
- \sessions\$x\AppContainerNamedObject\SID

*/


namespace pwn::windows::filesystem
{

///
/// @brief Open a file from the filesystem
///
/// @param path
/// @param perm
/// @return HANDLE
///
PWNAPI auto
open(std::wstring_view const& path, std::wstring_view const& perm = L"rw") -> Result<HANDLE>;

///
/// @brief Same as touch() on Linux
///
/// @param path
/// @return Result<HANDLE>
///
PWNAPI auto
touch(const std::wstring_view& path) -> bool;

///
/// @brief Create a hardlink object
///
/// @param link
/// @param target
/// @return Result<HANDLE>
///
// PWNAPI auto
// create_hardlink(const std::wstring_view& link, const std::wstring_view& target) -> Result<HANDLE>;

///
/// @brief Create a symlink in the object manager. The link doesn't need to be deleted, as the
/// Object Manager will do it when the refcount of handles on the object reaches 0.
///
/// @param link
/// @param target
/// @return Result<HANDLE>
///
PWNAPI auto
create_symlink(const std::wstring_view& link, const std::wstring_view& target) -> Result<HANDLE>;

///
/// @brief Wrapper for NtOpenSymbolicLinkObject
/// See https://docs.microsoft.com/en-us/windows/win32/devnotes/ntopensymboliclinkobject
///
/// @param link
/// @return Result<HANDLE>
///
PWNAPI auto
open_symlink(const std::wstring_view& link) -> Result<HANDLE>;

///
// PWNAPI auto
// create_junction(const std::wstring& link, const std::wstring& target) -> Result<HANDLE>;


///
/// @brief Make a directory - and recursively create its parent(s)
///
/// @param name
/// @return Result<bool>
///
PWNAPI auto
mkdir(const std::wstring_view& name) -> Result<bool>;


///
/// @brief Delete a directory, and its sub-directories
///
/// @param name
/// @return Result<bool>
///
PWNAPI auto
rmdir(const std::wstring_view& name) -> Result<bool>;


///
/// @brief Create a temporary directory
///
/// @param level
/// @return std::wstring
///
PWNAPI auto
make_tmpdir(int level = 10) -> Result<std::wstring>;

///
/// @brief Create a temporary file
///
/// @param prefix
/// @return Result<std::tuple<std::wstring path, HANDLE>>
///
PWNAPI auto
tmpfile(const std::wstring_view& prefix) -> Result<std::tuple<std::wstring, HANDLE>>;


///
/// @brief Watch directory and invoke callback when an event occured.
///
/// @param name
/// @param cbFunctor
/// @param watch_subtree
/// @return true
/// @return false
///
PWNAPI auto
watch_directory(
    const std::wstring_view& name,
    std::function<bool(PFILE_NOTIFY_INFORMATION)> cbFunctor,
    const bool watch_subtree = false) -> Result<bool>;

} // namespace pwn::windows::filesystem


//
// Creating namespace alias
//
namespace pwn::windows
{
namespace fs = filesystem;
}
