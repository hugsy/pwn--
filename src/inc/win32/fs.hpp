#pragma once

#include "common.hpp"
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
	PWNAPI auto open(
		_In_ std::wstring const& path,
		_In_ std::wstring const& perm = L"rw"
	) -> HANDLE;

	_Success_(return != nullptr)
	PWNAPI auto touch(
		_In_ const std::wstring& path
	) -> HANDLE;

	_Success_(return != nullptr)
	PWNAPI auto create_hardlink(
			_In_ const std::wstring & link,
			_In_ const std::wstring & target
	) -> HANDLE;

	_Success_(return != nullptr)
	PWNAPI auto create_symlink(
		_In_ const std::wstring& link,
		_In_ const std::wstring& target
	) -> HANDLE;

	_Success_(return != nullptr)
	PWNAPI auto open_symlink(
		_In_ const std::wstring & link
	) -> HANDLE;

	_Success_(return != nullptr)
		PWNAPI auto create_junction(
		_In_ const std::wstring& link,
		_In_ const std::wstring& target
	) -> HANDLE;

	_Success_(return)
	PWNAPI auto mkdir(
		_In_ const std::wstring& name
	) -> bool;

	_Success_(return)
	PWNAPI auto rmdir(
		_In_ const std::wstring& name
	) -> bool;

	PWNAPI auto make_tmpdir(
		_In_ int level = 10
	) -> std::wstring;

	_Success_(return != nullptr)
	PWNAPI auto tmpfile(
		_In_ const std::wstring& prefix,
		_Out_ std::wstring& path
	) -> HANDLE;

	/*++

	Watch directory and invoke callback when an event occured.

	--*/
	_Success_(return)
	PWNAPI auto watch_dir(
		_In_ const std::wstring& name,
		_In_ std::function<bool(PFILE_NOTIFY_INFORMATION)> cbFunctor,
		_In_ bool watch_subtree = false
	) -> bool;
}


