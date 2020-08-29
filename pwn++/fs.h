#pragma once

#include "common.h"

/*

interesting locations from link target

- \rpc control\
- \sessions\$x\BaseNamedObjects
- \sessions\$x\AppContainerNamedObject\SID

*/



#ifndef SYMBOLIC_LINK_ALL_ACCESS 
#define SYMBOLIC_LINK_ALL_ACCESS (STANDARD_RIGHTS_REQUIRED | 0x1)
#endif


namespace pwn::fs
{
	_Success_(return != nullptr)
	PWNAPI HANDLE touch(
		_In_ const std::wstring& path
	);

	_Success_(return != nullptr)
	PWNAPI HANDLE create_symlink(
		_In_ const std::wstring& link,
		_In_ const std::wstring& target
	);

	_Success_(return != nullptr)
	PWNAPI HANDLE open_symlink(
		_In_ const std::wstring & link
	);

	_Success_(return != nullptr)
		PWNAPI HANDLE create_junction(
		_In_ const std::wstring& link,
		_In_ const std::wstring& target
	);

	_Success_(return)
	PWNAPI bool mkdir(
		_In_ const std::wstring& name
	);

	_Success_(return)
	PWNAPI bool rmdir(
		_In_ const std::wstring& name
	);

	PWNAPI std::wstring make_tmpdir(
		void
	);

	PWNAPI bool watch_dir(
		_In_ const std::wstring& name
	);
}


