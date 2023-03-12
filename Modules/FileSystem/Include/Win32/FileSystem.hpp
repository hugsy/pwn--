#pragma once

#include <functional>
#include <string_view>
#include <tuple>

#include "Common.hpp"
#include "Handle.hpp"
#include "Resolver.hpp"
#include "Utils.hpp"

/*

interesting locations from link target

- \rpc control\
- \sessions\$x\BaseNamedObjects
- \sessions\$x\AppContainerNamedObject\SID

*/


namespace pwn::FileSystem
{
using FileMapViewHandle = GenericHandle<void, ::UnmapViewOfFile>;

class File
{
public:
    ///
    ///@brief Construct a new File object from a path
    ///
    ///@param FilePath
    ///
    File(std::filesystem::path const& FilePath)
    {
        if ( !std::filesystem::exists(FilePath) )
        {
            return;
        }

        auto hFile = Open(FilePath.wstring(), L"rw");
        if ( Success(hFile) )
        {
            m_hFile = UniqueHandle {Value(hFile)};
        }
    }


    ///
    ///@brief Move-Construct a new File object from a handle
    ///
    ///@param hFile
    ///
    File(HANDLE&& hFile) : m_hFile {UniqueHandle {hFile}}
    {
    }


    ///
    ///@brief Construct a new File object from a handle, but will also duplicate it
    ///
    ///@param hFile
    ///
    File(HANDLE const& hFile)
    {
        HANDLE h;
        if ( ::DuplicateHandle(
                 ::GetCurrentProcess(),
                 hFile,
                 ::GetCurrentProcess(),
                 &h,
                 DUPLICATE_SAME_ACCESS,
                 true,
                 0) )
        {
            m_hFile = UniqueHandle {h};
        }
    }


    ///
    ///@brief Access the file handle directly
    ///
    ///@return HANDLE
    ///
    HANDLE
    Handle() const;


    ///
    ///@brief Forcefully close the handle
    ///
    void
    Close();


    ///
    ///@brief Get the file size
    ///
    ///@return usize
    ///
    Result<usize>
    Size();


    ///
    ///@brief Create a file mapping with the given protection
    ///
    ///@param Protect
    ///@param Name (opt.)
    ///@return Result<HANDLE>
    ///
    Result<HANDLE>
    Map(DWORD Protect, std::optional<std::wstring_view> Name = std::nullopt);


    ///
    ///@brief
    ///
    ///@param hFileMappingObject
    ///@param Protect
    ///@param Offset
    ///@param Size
    ///@return Result<PVOID>
    ///
    Result<PVOID>
    View(HANDLE hMap, DWORD Protect, uptr Offset = 0, usize Size = -1);


    ///
    ///@brief Export a portion of the file to a vector of bytes
    ///
    ///@param Offset
    ///@param Size
    ///@return Result<std::vector<u8>>
    ///
    Result<std::vector<u8>>
    ToBytes(uptr Offset, usize Size);


    ///
    ///@brief Query file information to the OS. This is a smart wrapper around `ntdll!NtQueryInformationFile`.
    ///
    ///@tparam T
    ///@param FileInformationClass
    ///@return Result<std::shared_ptr<T>>
    ///
    template<class T>
    Result<std::shared_ptr<T>>
    Query(FILE_INFORMATION_CLASS FileInformationClass)
    {
        auto res = QueryInternal(FileInformationClass, sizeof(T));
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
    ///@tparam T
    ///@param FileInformationClass
    ///@param FileInformationData
    ///@return Result<void>
    ///
    template<class T>
    Result<bool>
    Set(FILE_INFORMATION_CLASS FileInformationClass, T& FileInformationData)
    {
        return SetInternal(FileInformationClass, reinterpret_cast<PVOID>(&FileInformationData), sizeof(T));
    }


    ///
    /// @brief Open a file from the filesystem
    ///
    /// @param Path
    /// @param Permission `r` -> Open(READ), `w` -> Open(WRITE), `rw` -> Open(READ|WRITE), `a` -> Create(READ|WRITE)
    /// @param IsTemporary if `true`, the file name will be randomized, and the file will be deleted on handle close
    /// @return HANDLE
    ///
    static auto
    Open(std::wstring_view const& Prefix, std::wstring_view const& Permission = L"rw", bool IsTemporary = false)
        -> Result<HANDLE>
    {
        DWORD Access {}, ShareMode {}, Disposition {}, Attrs {FILE_ATTRIBUTE_NORMAL};
        std::wstring path = std::wstring(Prefix);

        if ( Permission.find(L"r") != std::wstring::npos )
        {
            Access |= GENERIC_READ;
            ShareMode |= FILE_SHARE_READ;
            Disposition = CREATE_NEW | OPEN_EXISTING;
        }

        if ( Permission.find(L"w") != std::wstring::npos )
        {
            Access |= GENERIC_WRITE;
            ShareMode |= FILE_SHARE_WRITE;
            Disposition = CREATE_NEW | OPEN_EXISTING;
        }

        if ( Permission == L"a" )
        {
            Access |= GENERIC_READ | GENERIC_WRITE;
            ShareMode |= FILE_SHARE_READ | FILE_SHARE_WRITE;
            Disposition = OPEN_EXISTING | TRUNCATE_EXISTING;
        }

        if ( IsTemporary )
        {
            Attrs |= FILE_FLAG_DELETE_ON_CLOSE;
            path += L"-" + Utils::Random::string(10);
        }

        HANDLE hFile = ::CreateFileW(path.data(), Access, ShareMode, nullptr, Disposition, Attrs, nullptr);
        if ( hFile == INVALID_HANDLE_VALUE )
        {
            return Err(ErrorCode::FilesystemError);
        }

        return Ok(hFile);
    }


private:
    ///
    /// @brief Should not be called directly
    ///
    /// @param FileInformationClass
    ///
    /// @return Result<PVOID>
    ///
    Result<PVOID>
    QueryInternal(const FILE_INFORMATION_CLASS, const usize);

    ///
    ///@brief Set the Internal object
    ///
    ///@tparam T
    ///@param FileInformationClass
    ///@param FileInformationData
    ///@return Result<void>
    ///
    Result<bool>
    SetInternal(
        const FILE_INFORMATION_CLASS FileInformationClass,
        const PVOID FileInformationData,
        const usize FileInformationDataSize);

    UniqueHandle m_hFile {};
};


namespace Symlink
{
///
/// @brief Create a symlink in the object manager. The link doesn't need to be deleted, as the
/// Object Manager will do it when the refcount of handles on the object reaches 0.
///
/// @param link
/// @param target
/// @return Result<UniqueHandle>
///
auto
CreateSymlink(const std::wstring_view& link, const std::wstring_view& target) -> Result<UniqueHandle>;

///
/// @brief Wrapper for NtOpenSymbolicLinkObject
/// See https://docs.microsoft.com/en-us/windows/win32/devnotes/ntopensymboliclinkobject
///
/// @param link
/// @return Result<UniqueHandle>
///
auto
OpenSymlink(const std::wstring_view& link) -> Result<UniqueHandle>;

///
/// @brief Create a junction object
///
/// @param link
/// @param target
/// @return Result<HANDLE>
/// TODO
// auto
// CreateJunction(const std::wstring& link, const std::wstring& target) -> Result<UniquePointer>;

///
/// @brief Create a hardlink object
///
/// @param link
/// @param target
/// @return Result<HANDLE>
/// TODO
// auto
// CreateHardlink(const std::wstring_view& link, const std::wstring_view& target) -> Result<UniquePointer>;
} // namespace Symlink


namespace Directory
{
///
/// @brief Make a directory - and recursively create its parent(s)
///
/// @param DirPath the path to create
/// @param IsTemporary if `true`, a temporary folder will be created inside `DirPath` and the complete path will be
/// returned
/// @return Result<std::wstring>
///
PWNAPI auto
Create(std::wstring_view& DirPath, bool IsTemporary = false) -> Result<std::wstring>;


///
/// @brief Delete a directory, and its sub-directories
///
/// @param name
/// @return Result<bool>
///
PWNAPI auto
Delete(const std::wstring_view& name) -> Result<bool>;


///
/// @brief Watch directory and invoke callback when an event occured.
///
/// @param name
/// @param cbFunctor
/// @param watch_subtree
/// @return true
/// @return false
///
auto
Watch(
    const std::wstring_view& name,
    std::function<bool(PFILE_NOTIFY_INFORMATION)> cbFunctor,
    const bool watch_subtree = false) -> Result<bool>;
} // namespace Directory

} // namespace pwn::FileSystem
