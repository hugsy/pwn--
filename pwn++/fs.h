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
	HANDLE create_symlink(
		_In_ const std::wstring link,
		_In_ const std::wstring target
	);


}


