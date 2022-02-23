#pragma once

#include "common.hpp"
#include "log.hpp"


namespace pwn::context
{
enum class architecture_t
{
    x86,
    x64,
    arm,
    arm_thumb,
    arm64,
    mips
};

enum class endianess_t
{
    little,
    big,
};

extern PWNAPI architecture_t arch;
extern PWNAPI endianess_t endian;
extern PWNAPI u8 ptrsize;
extern PWNAPI pwn::log::log_level_t __log_level;

/**
 * @brief Set the architecture to use for the current context.
 *
 * @param new_arch
 * @return true
 * @return false
 */
PWNAPI auto
set_architecture(_In_ architecture_t new_arch) -> bool;

/**
 * @brief Set the log level object
 *
 * @param new_level
 * @return true
 * @return false
 */
PWNAPI auto
set_log_level(_In_ pwn::log::log_level_t new_level) -> bool;

/**
 * @brief Get the log level object
 *
 * @return const std::tuple<pwn::log::log_level_t, const wchar_t*>
 */
PWNAPI auto
get_log_level() -> const std::tuple<pwn::log::log_level_t, const wchar_t*>;

} // namespace pwn::context