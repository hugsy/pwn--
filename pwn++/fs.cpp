#include "fs.h"
#include "nt.h"
#include "utils.h"
#include "log.h"

#include <sstream>


/*++
* 
* Resources:
* https://github.com/googleprojectzero/symboliclink-testing-tools/
*
--*/

extern "C" {
	NTSTATUS NTAPI NtCreateSymbolicLinkObject(PHANDLE LinkHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PUNICODE_STRING TargetName);
	NTSTATUS NTAPI NtOpenSymbolicLinkObject(
		_Out_ PHANDLE            LinkHandle,
		_In_  ACCESS_MASK        DesiredAccess,
		_In_  POBJECT_ATTRIBUTES ObjectAttributes
	);

}


_Success_(return != nullptr)
HANDLE pwn::fs::touch(_In_ const std::wstring & path)
{
	return ::CreateFile(
		path.c_str(),
		GENERIC_READ | GENERIC_WRITE,
		FILE_SHARE_READ,
		nullptr,
		CREATE_ALWAYS,
		FILE_ATTRIBUTE_NORMAL,
		nullptr
	);
}


/*++

Create a symlink in the object manager. The link doesn't need to be deleted, as the ObjMan will 
do it when the refcount of handles on the object reaches 0.

--*/
_Success_ (return != nullptr)
HANDLE pwn::fs::create_symlink(
	_In_ const std::wstring& link, 
	_In_ const std::wstring& target
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
	{
		dbg(L"created link '%s' to '%s' (h=%p)\n", link.c_str(), target.c_str(), hLink);
		return hLink;
	}

	return nullptr;
}


/*++
* 
* wrapper for NtOpenSymbolicLinkObject 
* https://docs.microsoft.com/en-us/windows/win32/devnotes/ntopensymboliclinkobject
* 
--*/
_Success_(return != nullptr)
HANDLE pwn::fs::open_symlink(
	_In_ const std::wstring &link
)
{
	HANDLE hLink = INVALID_HANDLE_VALUE;
	OBJECT_ATTRIBUTES oa = { 0 };
	UNICODE_STRING link_name;
	::RtlInitUnicodeString(&link_name, link.c_str());

	InitializeObjectAttributes(
		&oa,
		&link_name,
		OBJ_CASE_INSENSITIVE,
		nullptr,
		nullptr
	);

	if (NT_SUCCESS(NtOpenSymbolicLinkObject(&hLink, SYMBOLIC_LINK_ALL_ACCESS, &oa)))
	{
		dbg(L"opened link '%s' with handle=%p)\n", link.c_str(), hLink);
		return hLink;
	}

	return nullptr;
}

_Success_(return != nullptr)
HANDLE pwn::fs::create_junction(
	_In_ const std::wstring& link,
	_In_ const std::wstring& target
)
{
	return INVALID_HANDLE_VALUE;
}


/*++

Create directories recursively.

--*/
_Success_(return)
bool pwn::fs::mkdir(_In_ const std::wstring& name)
{
	bool bRes = true;
	std::wstring root = L"";

	for (auto subdir : pwn::utils::split(name, L'\\'))
	{
		if (::CreateDirectory((root + subdir).c_str(), NULL) 
			|| ::GetLastError() == ERROR_ALREADY_EXISTS)
		{
			root = root + L"\\" + subdir;
			continue;
		}

		bRes = false;
		break;
	}
	
	return bRes;
}


_Success_(return)
bool pwn::fs::rmdir(_In_ const std::wstring& name)
{
	return ::RemoveDirectoryW(name.c_str());
}


std::wstring pwn::fs::make_tmpdir()
{
	std::wstring name;

	do
	{
		name = pwn::utils::random::string(10);
		name.erase(62);
	}
	while (mkdir(name) == false);

	dbg(L"created tmp dir '%s'\n", name.c_str());

	return name;
}


bool pwn::fs::watch_dir(const std::wstring& name)
{
	return true;
}
