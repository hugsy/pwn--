#include "fs.h"
#include "nt.h"
#include "utils.h"
#include "log.h"
#include "handle.h"

#include <sstream>


/*++
* 
* Resources:
* https://github.com/googleprojectzero/symboliclink-testing-tools/
*
--*/

extern "C" 
{
	NTSTATUS NTAPI NtCreateSymbolicLinkObject(
		PHANDLE LinkHandle, 
		ACCESS_MASK DesiredAccess, 
		POBJECT_ATTRIBUTES ObjectAttributes, 
		PUNICODE_STRING TargetName
	);

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


_Success_(return != nullptr)
HANDLE pwn::fs::tmpfile(_In_ const std::wstring & prefix, _Out_ std::wstring& path)
{
	HANDLE h = INVALID_HANDLE_VALUE;

	do
	{
		path = prefix + L"-" + pwn::utils::random::string(10);
		h = ::CreateFile(
			path.c_str(),
			GENERIC_READ | GENERIC_WRITE,
			0,
			nullptr,
			CREATE_ALWAYS,
			FILE_ATTRIBUTE_NORMAL | FILE_FLAG_DELETE_ON_CLOSE,
			nullptr
		);
	}
	while (h == INVALID_HANDLE_VALUE);

	

	return h;
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


std::wstring pwn::fs::make_tmpdir(_In_ int level)
{
	std::wstring name;
	auto max_attempts = 10, attempts = 0;

	do
	{
		if (attempts == max_attempts)
			throw std::exception("failed to create directory");

		name = pwn::utils::random::string(level);
		name.erase(62);
		attempts++;
	}
	while (mkdir(name) == false);

	dbg(L"created tmp dir '%s'\n", name.c_str());

	return name;
}


_Success_(return)
bool pwn::fs::watch_dir(_In_ const std::wstring& name, _In_ std::function<bool(PFILE_NOTIFY_INFORMATION)> cbFunctor, _In_ bool watch_subtree)
{
	auto h = pwn::generic::GenericHandle(
		::CreateFileW(
			name.c_str(),
			GENERIC_READ,
			FILE_SHARE_READ,
			nullptr,
			OPEN_EXISTING,
			FILE_FLAG_BACKUP_SEMANTICS,
			nullptr
		)
	);

	if (!h)
		return false;

	DWORD sz = (DWORD)sizeof(FILE_NOTIFY_INFORMATION);
	auto buffer = std::make_unique<std::byte[]>(sz);
	DWORD bytes_written;

	dbg(L"watching %s\n", name.c_str());

	// https://docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-readdirectorychangesw

	if (!::ReadDirectoryChangesW(
		h.get(),
		buffer.get(),
		sz,
		watch_subtree,
		FILE_NOTIFY_CHANGE_FILE_NAME,
		&bytes_written,
		nullptr,
		nullptr
		))
	{
		return false;
	}

	auto info = reinterpret_cast<PFILE_NOTIFY_INFORMATION>(buffer.get());
	return cbFunctor(info);
}
