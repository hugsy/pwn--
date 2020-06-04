#include "fs.h"

#include "nt.h"


/*++

This whole module is a bad re-implem of all that James Forshaw did way better in 
https://github.com/googleprojectzero/symboliclink-testing-tools/

--*/


/*++

Create a symlink in the object manager. The link doesn't need to be deleted, as the ObjMan will 
do it when the refcount of handles on the object reaches 0.

--*/
_Success_ (return != nullptr)
HANDLE pwn::fs::create_symlink(
	_In_ const std::wstring link, 
	_In_ const std::wstring target
)
{
	OBJECT_ATTRIBUTES oa = { 0 };
	HANDLE hLink = nullptr;

	UNICODE_STRING link_name, target_name;
	
	::RtlInitUnicodeString(&link_name, link.c_str());
	::RtlInitUnicodeString(&target_name, target.c_str());

	InitializeObjectAttributes(
		&oa,
		&link_name,
		OBJ_CASE_INSENSITIVE,
		nullptr,
		nullptr
	);

	if (NT_SUCCESS(NtCreateSymbolicLinkObject(&hLink, SYMBOLIC_LINK_ALL_ACCESS, &oa, &target_name)))
		return hLink;

	return nullptr;
}