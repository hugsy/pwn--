#include "Linux/System.hpp"

namespace pwn::Linux::System
{

u32
PageSize()
{
    return ::getpagesize();
}

} // namespace pwn::Linux::System
