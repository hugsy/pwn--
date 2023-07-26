#include "Win32/FileSystem.hpp"

#include "Handle.hpp"
#include "Log.hpp"
#include "Utils.hpp"
#include "Win32/API.hpp"


#ifndef SYMBOLIC_LINK_ALL_ACCESS
#define SYMBOLIC_LINK_ALL_ACCESS (STANDARD_RIGHTS_REQUIRED | 0x1)
#endif

using namespace pwn;

namespace pwn::FileSystem
{

Result<usize>
File::Size()
{
    if ( !m_hFile )
    {
        return Err(ErrorCode::NotInitialized);
    }

    LARGE_INTEGER FileSize {};
    if ( !::GetFileSizeEx(m_hFile.get(), &FileSize) )
    {
        return Err(ErrorCode::ExternalApiCallFailed);
    }
#ifdef _WIN64
    return Ok((usize)FileSize.QuadPart);
#else
    return Ok(FileSize.u.LowPart);
#endif
}


HANDLE
File::Handle() const
{
    return m_hFile.get();
}


bool
File::IsValid() const
{
    return Handle() != nullptr && Handle() != INVALID_HANDLE_VALUE;
}


bool
File::IsTemporary() const
{
    return IsValid() && m_IsTemporary;
}


void
File::Close()
{
    ::CloseHandle(m_hFile.get());
}


Result<std::vector<u8>>
File::ToBytes(uptr Offset, usize Size)
{
    if ( !m_hFile )
    {
        return Err(ErrorCode::NotInitialized);
    }

    auto map = Map(PAGE_READONLY);
    if ( Failed(map) )
    {
        return Error(map);
    }

    auto hMap = UniqueHandle {Value(std::move(map))};
    auto view = View(hMap.get(), FILE_MAP_READ, Offset, Size);
    if ( Failed(view) )
    {
        return Error(view);
    }

    auto hView = Value(std::move(view));
    std::vector<u8> bytes(Size);
    ::memcpy(bytes.data(), hView.get(), bytes.size());

    return Ok(bytes);
}


Result<PVOID>
File::QueryInternal(const FILE_INFORMATION_CLASS FileInformationClass, const usize InitialSize)
{
    usize Size  = InitialSize;
    auto Buffer = ::LocalAlloc(LPTR, Size);
    if ( !Buffer )
    {
        return Err(ErrorCode::AllocationError);
    }

    do
    {
        IO_STATUS_BLOCK iosb {};
        NTSTATUS Status =
            Resolver::ntdll::NtQueryInformationFile(m_hFile.get(), &iosb, Buffer, Size, FileInformationClass);

        if ( NT_SUCCESS(Status) )
        {
            break;
        }

        if ( Status == STATUS_INFO_LENGTH_MISMATCH )
        {
            Size   = Size * 2;
            Buffer = ::LocalReAlloc(Buffer, Size, LMEM_ZEROINIT);
            continue;
        }

        Log::ntperror(L"NtQueryInformationFile()", Status);
        return Err(ErrorCode::PermissionDenied);

    } while ( true );

    return Ok(Buffer);
}


Result<bool>
File::SetInternal(
    const FILE_INFORMATION_CLASS FileInformationClass,
    const PVOID FileInformationData,
    const usize FileInformationDataSize)
{
    IO_STATUS_BLOCK iosb {};
    NTSTATUS Status = Resolver::ntdll::NtSetInformationFile(
        m_hFile.get(),
        &iosb,
        FileInformationData,
        FileInformationDataSize,
        FileInformationClass);
    if ( !NT_SUCCESS(Status) )
    {
        return Err(ErrorCode::ExternalApiCallFailed);
    }

    return Ok(true);
}


Result<bool>
File::ReOpenFileWith(const DWORD DesiredAccess, const DWORD DesiredShareMode, const DWORD DesiredAttributes)
{
    if ( !IsValid() )
    {
        return Err(ErrorCode::InvalidState);
    }

    if ( (m_Access & DesiredAccess) == DesiredAccess )
    {
        return Ok(true);
    }

    const DWORD NewAccessMask = m_Access | DesiredAccess;
    const DWORD NewShareMode  = m_ShareMode | DesiredShareMode;
    const DWORD NewAttributes = m_Attributes | DesiredAttributes;
    const HANDLE hFile        = ::ReOpenFile(m_hFile.get(), NewAccessMask, NewShareMode, DesiredAttributes);
    if ( hFile == INVALID_HANDLE_VALUE )
    {
        return Err(ErrorCode::ExternalApiCallFailed);
    }

    m_hFile      = UniqueHandle(hFile); // this will close the initial handle
    m_Access     = NewAccessMask;
    m_ShareMode  = NewShareMode;
    m_Attributes = NewAttributes;

    return Ok(true);
}


Result<UniqueHandle>
File::Map(DWORD Protect, std::optional<std::wstring_view> Name)
{
    HANDLE h = {::CreateFileMappingW(m_hFile.get(), nullptr, Protect, 0, 0, Name.value_or(std::wstring {L""}).data())};
    if ( !h )
    {
        return Err(ErrorCode::ExternalApiCallFailed);
    }

    return Ok(UniqueHandle {h});
}


Result<FileMapViewHandle>
File::View(HANDLE hMap, DWORD Protect, uptr Offset, usize Size)
{
    Size       = (Size == (usize)-1) ? ValueOr(this->Size(), (usize)0) : Size;
    LPVOID map = ::MapViewOfFile(
        hMap,
        Protect,
#ifdef _WIN64
        Offset >> 32,
#else
        0,
#endif
        Offset & 0xffff'ffff,
        Size);
    if ( !map )
    {
        return Err(ErrorCode::ExternalApiCallFailed);
    }

    return Ok(FileMapViewHandle {map});
}


auto
Directory::Create(std::wstring_view& DirPath, bool IsTemporary) -> Result<std::wstring>
{
    std::wstring root = L"";

    for ( auto subdir : Utils::StringLib::Split(std::wstring(DirPath), L'\\') )
    {
        if ( (::CreateDirectoryW((root + subdir).c_str(), nullptr) != 0) || ::GetLastError() == ERROR_ALREADY_EXISTS )
        {
            root += L"\\" + subdir;
            continue;
        }

        return Err(ErrorCode::FilesystemError);
    }

    if ( !IsTemporary )
    {
        return Ok(root);
    }

    std::wstring TmpDir = root + L"\\" + L"Pwn" + Utils::Random::WideString(10);
    if ( ::CreateDirectoryW(TmpDir.c_str(), nullptr) )
    {
        return Ok(TmpDir);
    }

    return Err(ErrorCode::FilesystemError);
}


auto
Directory::Delete(const std::wstring_view& name) -> Result<bool>
{
    return Ok(::RemoveDirectoryW(name.data()) != 0);
}


auto
Directory::Watch(
    const std::wstring_view& name,
    std::function<bool(PFILE_NOTIFY_INFORMATION)> cbFunctor,
    const bool watch_subtree) -> Result<bool>
{
    auto h = std::make_unique<UniqueHandle>(::CreateFileW(
        name.data(),
        GENERIC_READ,
        FILE_SHARE_READ,
        nullptr,
        OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS,
        nullptr));

    if ( !h )
    {
        Log::perror(L"CreateFileW()");
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
        Log::perror(L"ReadDirectoryChangesW()");
        return Err(ErrorCode::FilesystemError);
    }

    auto info = reinterpret_cast<PFILE_NOTIFY_INFORMATION>(buffer.get());
    return Ok(cbFunctor(info));
}


auto
Symlink::CreateSymlink(const std::wstring_view& link, const std::wstring_view& target) -> Result<UniqueHandle>
{
    OBJECT_ATTRIBUTES oa       = {0};
    HANDLE hLink               = nullptr;
    UNICODE_STRING link_name   = RTL_CONSTANT_STRING((PWCH)link.data());
    UNICODE_STRING target_name = RTL_CONSTANT_STRING((PWCH)target.data());

    InitializeObjectAttributes(&oa, &link_name, OBJ_CASE_INSENSITIVE, nullptr, nullptr);

    if ( !NT_SUCCESS(Resolver::ntdll::NtCreateSymbolicLinkObject(&hLink, SYMBOLIC_LINK_ALL_ACCESS, &oa, &target_name)) )
    {
        return Err(ErrorCode::FilesystemError);
    }

    dbg(L"created link '{}' to '{}' (h={})", link, target, hLink);
    return Ok(UniqueHandle {hLink});
}


auto
Symlink::OpenSymlink(const std::wstring_view& link) -> Result<UniqueHandle>
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
    return Ok(UniqueHandle {hLink});
}


} // namespace pwn::FileSystem
