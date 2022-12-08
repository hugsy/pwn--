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
    try
    {
        architecture = Architecture::Find(type);
        endianess    = architecture.endian;
        ptrsize      = architecture.ptrsize;

        dbg("Selecting {}", architecture);
    }
    catch ( std::range_error const& e )
    {
        err("Invalid architecture '{}'. Value must be in:", type);
        for ( auto const& [name, arch] : Architectures )
        {
            err("- {}", arch);
        }
    }
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
