#include "Win32/ObjectManager.hpp"

#include "Handle.hpp"
#include "Log.hpp"
#include "Win32/API.hpp"
#include "Win32/System.hpp"

using namespace pwn;

namespace pwn::System
{

Result<std::vector<std::pair<std::wstring, std::wstring>>>
ObjectManager::EnumerateDirectory(std::wstring_view const& Root)
{
    NTSTATUS Status = STATUS_SUCCESS;

    std::vector<std::pair<std::wstring, std::wstring>> ObjectList;

    UniqueHandle hDirectory;
    ULONG EnumerationContext = 0;

    {
        HANDLE h;
        OBJECT_ATTRIBUTES oa;
        UNICODE_STRING name;

        ::RtlInitUnicodeString(&name, Root.data());
        InitializeObjectAttributes(&oa, &name, OBJ_CASE_INSENSITIVE, nullptr, nullptr);

        Status = Resolver::ntdll::NtOpenDirectoryObject(&h, DIRECTORY_QUERY | DIRECTORY_TRAVERSE, &oa);
        if ( !NT_SUCCESS(Status) )
        {
            Log::ntperror(L"NtOpenDirectoryObject()", Status);
            return Err(ErrorCode::InsufficientPrivilegeError);
        }

        hDirectory = UniqueHandle {h};
    }

    do
    {
        ULONG RequiredLength = 0;

        Status = Resolver::ntdll::NtQueryDirectoryObject(
            hDirectory.get(),
            nullptr,
            0,
            true,
            false,
            &EnumerationContext,
            &RequiredLength);
        if ( Status == STATUS_NO_MORE_ENTRIES )
        {
            break;
        }

        if ( Status != STATUS_BUFFER_TOO_SMALL )
        {
            Log::ntperror(L"NtQueryDirectoryObject()", Status);
            return Err(ErrorCode::BufferTooSmall);
        }

        auto Buffer = std::make_unique<u8[]>(RequiredLength);
        if ( !Buffer )
        {
            return Err(ErrorCode::AllocationError);
        }

        auto pObjDirInfo = reinterpret_cast<POBJECT_DIRECTORY_INFORMATION>(Buffer.get());

        Status = Resolver::ntdll::NtQueryDirectoryObject(
            hDirectory.get(),
            pObjDirInfo,
            RequiredLength,
            true,
            false,
            &EnumerationContext,
            &RequiredLength);
        if ( !NT_SUCCESS(Status) )
        {
            Log::ntperror(L"NtQueryDirectoryObject()", Status);
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


Result<std::vector<uptr>>
ObjectManager::FindBigPoolAddressesFromTag(const u32 Tag)
{
    auto res = System::Query<SYSTEM_BIGPOOL_INFORMATION>(SystemBigPoolInformation);
    if ( Failed(res) )
    {
        return Err(ErrorCode::ExternalApiCallFailed);
    }

    auto BigPoolInfo = Value(res);
    if ( BigPoolInfo->Count == 0 )
    {
        return Err(ErrorCode::NotFound);
    }

    std::vector<uptr> Pools;
    auto AllocatedInfos =
        std::span<SYSTEM_BIGPOOL_ENTRY>((SYSTEM_BIGPOOL_ENTRY*)BigPoolInfo->AllocatedInfo, (usize)BigPoolInfo->Count);

    for ( auto const& Entry : AllocatedInfos )
    {
        if ( Tag == 0 || Entry.TagUlong == Tag )
        {
            Pools.push_back((uptr)Entry.VirtualAddress);
        }
    }
    return Ok(Pools);
}

} // namespace pwn::System
