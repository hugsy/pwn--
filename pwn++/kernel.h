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
	PWNAPI ULONG_PTR get_module_base_address(_In_ const std::wstring& ModuleName);
	PWNAPI ULONG_PTR get_handle_kaddress(_In_ HANDLE hTarget, _In_ DWORD dwPid);
	PWNAPI std::vector<ULONG_PTR> get_big_pool_kaddress(_In_ DWORD Tag);

}


