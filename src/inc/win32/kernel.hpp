#pragma once

#include "common.hpp"


namespace pwn::windows::kernel
{
namespace shellcode
{
PWNAPI auto
steal_system_token() -> std::vector<u8>;
PWNAPI auto
debug_break() -> std::vector<u8>;
} // namespace shellcode

PWNAPI auto
modules() -> std::vector<std::tuple<std::wstring, uptr> >;
PWNAPI auto
get_module_base_address(_In_ const std::wstring& ModuleName) -> uptr;
PWNAPI auto
get_handle_kernel_address(_In_ HANDLE hTarget, _In_ u32 dwPid) -> uptr;
PWNAPI auto
get_big_pool_kaddress(_In_ u32 Tag) -> std::vector<uptr>;

} // namespace pwn::windows::kernel
