#pragma once

#include <optional>

#include "common.h"
#include "handle.h"
#include "pwn.h"
#include "utils.h"


#define BACKDOOR_PIPENAME L"\\\\.\\pipe\\WindowsBackup_" STR(__STDC_VERSION) L"_" STR(__TIME__)
#define BACKDOOR_MAX_MESSAGE_SIZE 2048


namespace pwn::backdoor
{

_Success_(return ) PWNAPI bool start();

_Success_(return ) PWNAPI bool stop();

}; // namespace pwn::backdoor
