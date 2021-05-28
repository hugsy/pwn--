#pragma once

#include "common.h"
#include <functional>

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
	PWNAPI HANDLE open(
		_In_ std::wstring const& path,
		_In_ std::wstring const& perm = L"rw"
	);

	_Success_(return != nullptr)
	PWNAPI HANDLE touch(
		_In_ const std::wstring& path
	);

	_Success_(return != nullptr)
	PWNAPI HANDLE create_hardlink(
			_In_ const std::wstring & link,
			_In_ const std::wstring & target
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
		_In_ int level = 10
	);

	_Success_(return != nullptr)
	PWNAPI HANDLE tmpfile(
		_In_ const std::wstring& prefix,
		_Out_ std::wstring& path
	);

	/*++
	
	Watch directory and invoke callback when an event occured.

	--*/
	_Success_(return)
	PWNAPI bool watch_dir(
		_In_ const std::wstring& name,
		_In_ std::function<bool(PFILE_NOTIFY_INFORMATION)> cbFunctor,
		_In_ bool watch_subtree = false
	);
}


