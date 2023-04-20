#include "linux/system.hpp"

namespace pwn::linux::system
{

auto
pagesize() -> u32
{
    return getpagesize();
}

}