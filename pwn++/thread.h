#pragma once

#include "common.h"
#include "nt.h"


namespace pwn::thread
{
	_Success_(return) PWNAPI bool start_backdoor();
	_Success_(return != nullptr) PWNAPI std::unique_ptr<std::wstring> get_name();
	_Success_(return) PWNAPI bool set_name(_In_ DWORD dwThreadId, _In_ const std::wstring& name);
	_Success_(return) PWNAPI bool set_name(_In_ DWORD dwThreadId, _In_ const PBYTE lpBuffer, _In_ WORD wBufferLength);
}