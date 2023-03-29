#include "pwn.hpp"


using namespace pwn::log;
using namespace pwn::utils::random;


static __attribute__((constructor)) void on_attach_routine(void)
{
}


static void __attribute__((destructor)) on_detach_routine()
{
}