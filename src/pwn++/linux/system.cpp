#include "linux\system.hpp"

#include <unistd.h>

namespace pwn::linux::system
{

auto
pagesize() -> u32
{
    return getpagesize();
}

}