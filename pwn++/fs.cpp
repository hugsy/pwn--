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
auto pwn::fs::open(_In_ std::wstring const& path, _In_ std::wstring const& perm) -> HANDLE
{
	DWORD dwPerm = 0;
	if (perm.find(L"r") != std::wstring::npos) { dwPerm |= GENERIC_READ;
}
	if (perm.find(L"w") != std::wstring::npos) { dwPerm |= GENERIC_WRITE;
}

	HANDLE hFile = ::CreateFile(
		path.c_str(),
		dwPerm,
		0x00000000,
		nullptr,
		CREATE_NEW,
		FILE_ATTRIBUTE_NORMAL,
		nullptr
	);
	if (hFile == INVALID_HANDLE_VALUE && ::GetLastError() == ERROR_FILE_EXISTS)
	{
		hFile = ::CreateFile(
			path.c_str(),
			dwPerm,
			0x00000000,
			nullptr,
			(perm.find(L"-") != std::wstring::npos) ? OPEN_EXISTING | TRUNCATE_EXISTING : OPEN_EXISTING,
			FILE_ATTRIBUTE_NORMAL,
			nullptr
		);
	}
	
	return hFile;
}


_Success_(return != nullptr)
auto pwn::fs::touch(_In_ const std::wstring & path) -> HANDLE
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
auto pwn::fs::tmpfile(_In_ const std::wstring & prefix, _Out_ std::wstring& path) -> HANDLE
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
auto pwn::fs::create_symlink(
	_In_ const std::wstring& link, 
	_In_ const std::wstring& target
) -> HANDLE
{
	OBJECT_ATTRIBUTES oa = { 0 };
	HANDLE hLink = nullptr;

	UNICODE_STRING link_name;
	UNICODE_STRING target_name;
	
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
auto pwn::fs::open_symlink(
	_In_ const std::wstring &link
) -> HANDLE
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
auto pwn::fs::create_junction(
	_In_ const std::wstring& link,
	_In_ const std::wstring& target
) -> HANDLE
{
	return INVALID_HANDLE_VALUE;
}


/*++

Create directories recursively.

--*/
_Success_(return)
auto pwn::fs::mkdir(_In_ const std::wstring& name) -> bool
{
	bool bRes = true;
	std::wstring root;

	for (auto subdir : pwn::utils::split(name, L'\\'))
	{
		if ((::CreateDirectory((root + subdir).c_str(), nullptr) != 0) 
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
auto pwn::fs::rmdir(_In_ const std::wstring& name) -> bool
{
	return ::RemoveDirectoryW(name.c_str()) != 0;
}


auto pwn::fs::make_tmpdir(_In_ int level) -> std::wstring
{
	std::wstring name;
	auto max_attempts = 10;
	auto attempts = 0;

	do
	{
		if (attempts == max_attempts) {
			throw std::exception("failed to create directory");
}

		name = pwn::utils::random::string(level);
		name.erase(62);
		attempts++;
	}
	while (!mkdir(name));

	dbg(L"created tmp dir '%s'\n", name.c_str());

	return name;
}


_Success_(return)
auto pwn::fs::watch_dir(_In_ const std::wstring& name, _In_ std::function<bool(PFILE_NOTIFY_INFORMATION)> cbFunctor, _In_ bool watch_subtree) -> bool
{
	auto h = pwn::utils::GenericHandle(
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

	if (!h) {
		return false;
}

	auto sz = (DWORD)sizeof(FILE_NOTIFY_INFORMATION);
	auto buffer = std::make_unique<std::byte[]>(sz);
	DWORD bytes_written;

	dbg(L"watching %s\n", name.c_str());

	// https://docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-readdirectorychangesw

	if (::ReadDirectoryChangesW(
		h.get(),
		buffer.get(),
		sz,
		static_cast<BOOL>(watch_subtree),
		FILE_NOTIFY_CHANGE_FILE_NAME,
		&bytes_written,
		nullptr,
		nullptr
		) == 0)
	{
		return false;
	}

	auto info = reinterpret_cast<PFILE_NOTIFY_INFORMATION>(buffer.get());
	return cbFunctor(info);
}
