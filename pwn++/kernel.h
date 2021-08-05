#pragma once

#include "common.h"

#include <winternl.h>




namespace pwn::kernel
{
	namespace shellcode
	{
		PWNAPI auto steal_system_token() -> std::vector<BYTE>;
		PWNAPI auto debug_break() -> std::vector<BYTE>;
	}


	PWNAPI auto modules() -> std::vector< std::tuple<std::wstring, ULONG_PTR> >;
	PWNAPI auto get_module_base_address(_In_ const std::wstring& ModuleName) -> ULONG_PTR;
	PWNAPI auto get_handle_kaddress(_In_ HANDLE hTarget, _In_ DWORD dwPid) -> ULONG_PTR;
	PWNAPI auto get_big_pool_kaddress(_In_ DWORD Tag) -> std::vector<ULONG_PTR>;

}


