#include "win32/object.hpp"

#include "handle.hpp"
#include "log.hpp"

namespace pwn::windows
{

Result<std::vector<std::pair<std::wstring, std::wstring>>>
ObjectManager::EnumerateDirectory(std::wstring_view const& Root)
{
    NTSTATUS Status = STATUS_SUCCESS;

    std::vector<std::pair<std::wstring, std::wstring>> ObjectList;

    pwn::UniqueHandle hDirectory;
    ULONG EnumerationContext = 0;

    {
        HANDLE h;
        OBJECT_ATTRIBUTES oa;
        UNICODE_STRING name;

        ::RtlInitUnicodeString(&name, Root.data());
        InitializeObjectAttributes(&oa, &name, OBJ_CASE_INSENSITIVE, nullptr, nullptr);

        Status = ::NtOpenDirectoryObject(&h, DIRECTORY_QUERY | DIRECTORY_TRAVERSE, &oa);
        if ( !NT_SUCCESS(Status) )
        {
            log::ntperror(L"NtOpenDirectoryObject()", Status);
            return Err(ErrorCode::InsufficientPrivilegeError);
        }

        hDirectory = pwn::UniqueHandle {h};
    }

    do
    {
        ULONG RequiredLength = 0;

        Status =
            ::NtQueryDirectoryObject(hDirectory.get(), nullptr, 0, true, false, &EnumerationContext, &RequiredLength);
        if ( Status == STATUS_NO_MORE_ENTRIES )
        {
            break;
        }

        if ( Status != STATUS_BUFFER_TOO_SMALL )
        {
            log::ntperror(L"NtQueryDirectoryObject()", Status);
            return Err(ErrorCode::BufferTooSmall);
        }

        auto Buffer = std::make_unique<u8[]>(RequiredLength);
        if ( !Buffer )
        {
            return Err(ErrorCode::AllocationError);
        }

        auto pObjDirInfo = reinterpret_cast<POBJECT_DIRECTORY_INFORMATION>(Buffer.get());

        Status = ::NtQueryDirectoryObject(
            hDirectory.get(),
            pObjDirInfo,
            RequiredLength,
            true,
            false,
            &EnumerationContext,
            &RequiredLength);
        if ( !NT_SUCCESS(Status) )
        {
            log::ntperror(L"NtQueryDirectoryObject()", Status);
            return Err(ErrorCode::ExternalApiCallFailed);
        }

        for ( ULONG i = 0; i < EnumerationContext; i++ )
        {
            if ( !pObjDirInfo[i].Name.Buffer || !pObjDirInfo[i].TypeName.Buffer )
            {
                break;
            }

            auto Object =
                std::make_pair(std::wstring(pObjDirInfo[i].Name.Buffer), std::wstring(pObjDirInfo[i].TypeName.Buffer));
            ObjectList.push_back(std::move(Object));
        }
    } while ( true );

    return Ok(ObjectList);
}

} // namespace pwn::windows
