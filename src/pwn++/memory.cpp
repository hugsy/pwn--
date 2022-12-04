#include "memory.hpp"

void
pwn::utils::swap(pwn::utils::MemoryView& x, pwn::utils::MemoryView& y) noexcept(noexcept(x.swap(y)))
{
    x.swap(y);
}
