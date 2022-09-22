#include "fs.hpp"

#include <sstream>

#include "handle.hpp"
#include "log.hpp"
#include "nt.hpp"
#include "utils.hpp"


#ifndef SYMBOLIC_LINK_ALL_ACCESS
#define SYMBOLIC_LINK_ALL_ACCESS (STANDARD_RIGHTS_REQUIRED | 0x1)
#endif

IMPORT_EXTERNAL_FUNCTION(
    L"ntdll.dll",
    NtCreateSymbolicLinkObject,
    NTSTATUS,
    PHANDLE LinkHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PUNICODE_STRING TargetName);

IMPORT_EXTERNAL_FUNCTION(
    L"ntdll.dll",
    NtOpenSymbolicLinkObject,
    NTSTATUS,
    PHANDLE LinkHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes);


auto
pwn::windows::filesystem::open(std::wstring_view const& path, std::wstring_view const& perm) -> Result<HANDLE>
{
    DWORD dwPerm = 0;
    if ( perm.find(L"r") != std::wstring::npos )
    {
        dwPerm |= GENERIC_READ;
    }
    if ( perm.find(L"w") != std::wstring::npos )
    {
        dwPerm |= GENERIC_WRITE;
    }

    HANDLE hFile = ::CreateFile(path.data(), dwPerm, 0x00000000, nullptr, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr);
    if ( hFile == INVALID_HANDLE_VALUE && ::GetLastError() == ERROR_FILE_EXISTS )
    {
        hFile = ::CreateFile(
            path.data(),
            dwPerm,
            0x00000000,
            nullptr,
            (perm.find(L"-") != std::wstring::npos) ? OPEN_EXISTING | TRUNCATE_EXISTING : OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            nullptr);
    }

    return Ok(hFile);
}


auto
pwn::windows::filesystem::touch(const std::wstring_view& path) -> bool
{
    return ::CloseHandle(::CreateFile(
        path.data(),
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ,
        nullptr,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        nullptr));
}


auto
pwn::windows::filesystem::create_symlink(const std::wstring_view& link, const std::wstring_view& target)
    -> Result<HANDLE>
{
    OBJECT_ATTRIBUTES oa = {0};
    HANDLE hLink         = nullptr;

    UNICODE_STRING link_name;
    UNICODE_STRING target_name;

    ::RtlInitUnicodeString(&link_name, link.data());
    ::RtlInitUnicodeString(&target_name, target.data());

    InitializeObjectAttributes(&oa, &link_name, OBJ_CASE_INSENSITIVE, nullptr, nullptr);

    if ( !NT_SUCCESS(NtCreateSymbolicLinkObject(&hLink, SYMBOLIC_LINK_ALL_ACCESS, &oa, &target_name)) )
    {
        return Err(ErrorCode::FilesystemError);
    }

    dbg(L"created link '{}' to '{}' (h={})", link, target, hLink);
    return Ok(hLink);
}


auto
pwn::windows::filesystem::open_symlink(const std::wstring_view& link) -> Result<HANDLE>
{
    HANDLE hLink         = INVALID_HANDLE_VALUE;
    OBJECT_ATTRIBUTES oa = {0};
    UNICODE_STRING link_name;
    ::RtlInitUnicodeString(&link_name, link.data());

    InitializeObjectAttributes(&oa, &link_name, OBJ_CASE_INSENSITIVE, nullptr, nullptr);

    if ( !NT_SUCCESS(NtOpenSymbolicLinkObject(&hLink, SYMBOLIC_LINK_ALL_ACCESS, &oa)) )
    {
        return Err(ErrorCode::FilesystemError);
    }

    dbg(L"opened link '{}' with handle={})\n", link, hLink);
    return Ok(hLink);
}


auto
pwn::windows::filesystem::mkdir(const std::wstring_view& name) -> Result<bool>
{
    std::wstring root = L"";

    for ( auto subdir : pwn::utils::split(std::wstring(name), L'\\') )
    {
        if ( (::CreateDirectoryW((root + subdir).c_str(), nullptr) != 0) || ::GetLastError() == ERROR_ALREADY_EXISTS )
        {
            root += L"\\" + subdir;
            continue;
        }

        return Err(ErrorCode::FilesystemError);
    }

    return Ok(true);
}


auto
pwn::windows::filesystem::rmdir(const std::wstring_view& name) -> Result<bool>
{
    return Ok(::RemoveDirectoryW(name.data()) != 0);
}


auto
pwn::windows::filesystem::make_tmpdir(int level) -> Result<std::wstring>
{
    std::wstring name;
    auto attempts = 5;

    do
    {
        attempts--;
        if ( attempts == 0 )
        {
            return Err(ErrorCode::FilesystemError);
        }

        name = pwn::utils::random::string(level);
        name.erase(62);

    } while ( Failed(mkdir(name)) );

    dbg(L"Created new temporary directory '{}'", name);
    return Ok(name);
}


auto
pwn::windows::filesystem::tmpfile(const std::wstring_view& prefix) -> Result<std::tuple<std::wstring, HANDLE>>
{
    std::wstring path = std::wstring(prefix);
    HANDLE hFile      = INVALID_HANDLE_VALUE;

    u32 max_attempt = 5;

    do
    {
        path += L"-" + pwn::utils::random::string(10);
        hFile = ::CreateFile(
            path.c_str(),
            GENERIC_READ | GENERIC_WRITE,
            0,
            nullptr,
            CREATE_ALWAYS,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_DELETE_ON_CLOSE,
            nullptr);

        if ( hFile != INVALID_HANDLE_VALUE )
        {
            return Ok(std::make_tuple(path, hFile));
        }

    } while ( max_attempt-- );

    return Err(ErrorCode::FilesystemError);
}


auto
pwn::windows::filesystem::watch_directory(
    const std::wstring_view& name,
    std::function<bool(PFILE_NOTIFY_INFORMATION)> cbFunctor,
    const bool watch_subtree) -> Result<bool>
{
    auto h = std::make_unique<pwn::UniqueHandle>(::CreateFileW(
        name.data(),
        GENERIC_READ,
        FILE_SHARE_READ,
        nullptr,
        OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS,
        nullptr));

    if ( !h )
    {
        pwn::log::perror(L"CreateFileW()");
        return Err(ErrorCode::FilesystemError);
    }

    auto sz     = (DWORD)sizeof(FILE_NOTIFY_INFORMATION);
    auto buffer = std::make_unique<std::byte[]>(sz);
    DWORD bytes_written;

    dbg(L"Start watching '{}'", name.data());

    if ( ::ReadDirectoryChangesW(
             h.get(),
             buffer.get(),
             sz,
             static_cast<BOOL>(watch_subtree),
             FILE_NOTIFY_CHANGE_FILE_NAME,
             &bytes_written,
             nullptr,
             nullptr) == 0 )
    {
        pwn::log::perror(L"ReadDirectoryChangesW()");
        return Err(ErrorCode::FilesystemError);
    }

    auto info = reinterpret_cast<PFILE_NOTIFY_INFORMATION>(buffer.get());
    return Ok(cbFunctor(info));
}
