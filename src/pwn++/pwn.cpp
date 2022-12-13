#include "pwn.hpp"


PWNAPI struct pwn::GlobalContext pwn::Context;

pwn::GlobalContext::GlobalContext()
{
    pwn::utils::random::seed(std::chrono::system_clock::now().time_since_epoch().count());
    set("x64");
};


void
pwn::GlobalContext::SetArchitecture(std::string_view const& type)
{
    architecture = Architecture::Find(type);
    endianess    = architecture.endian;
    ptrsize      = architecture.ptrsize;
    dbg("Selecting '{}'", architecture);
}


void
pwn::GlobalContext::SetEndianess(Endianess end)
{
    endianess = end;
}


void
pwn::GlobalContext::SetLogLevel(log::LogLevel new_log_level)
{
    LogLevel = new_log_level;
    if ( LogLevel == log::LogLevel::Debug )
    {
        dbg("Setting DEBUG log level");
    }
}
