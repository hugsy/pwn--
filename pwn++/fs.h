#pragma once

#include "common.h"

/*

interesting locations from link target

- \rpc control\
- \sessions\$x\BaseNamedObjects
- \sessions\$x\AppContainerNamedObject\SID

*/
extern "C" {
	NTSTATUS NTAPI NtCreateSymbolicLinkObject(PHANDLE LinkHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PUNICODE_STRING TargetName);
}


#ifndef SYMBOLIC_LINK_ALL_ACCESS 
#define SYMBOLIC_LINK_ALL_ACCESS (STANDARD_RIGHTS_REQUIRED | 0x1)
#endif


namespace pwn::fs
{
	PWNAPI HANDLE create_symlink(
		_In_ const std::wstring& link,
		_In_ const std::wstring& target
	);

	PWNAPI bool mkdir(
		_In_ const std::wstring& name
	);

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


