#pragma once

#include "common.h"

#include <winternl.h>


namespace pwn::kernel
{
	namespace shellcode
	{
		PWNAPI std::vector<BYTE> steal_system_token(void);
		PWNAPI std::vector<BYTE> debug_break(void);
	}


	PWNAPI std::vector< std::tuple<std::wstring, ULONG_PTR> > modules();
	PWNAPI ULONG_PTR get_module_base_address(_In_ const wchar_t* lpwszModuleName);
	PWNAPI ULONG_PTR get_module_base_address(_In_ const std::wstring& ModuleName);
	PWNAPI ULONG_PTR get_handle_kaddress(_In_ HANDLE hTarget);
	PWNAPI ULONG_PTR get_big_pool_kaddress(_In_ SIZE_T PoolSize, _In_ u32 Tag);

}

