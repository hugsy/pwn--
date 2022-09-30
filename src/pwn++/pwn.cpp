#include "pwn.hpp"


PWNAPI struct pwn::GlobalContext pwn::Context;

pwn::GlobalContext::GlobalContext()
{
    m_seed = std::chrono::system_clock::now().time_since_epoch().count();
    std::srand(m_seed);
    set("x64");
};


void
pwn::GlobalContext::set(std::string_view const& type)
{
    try
    {
        architecture = lookup_architecture(type);
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
pwn::GlobalContext::set(Endianess end)
{
    endianess = end;
}

void
pwn::GlobalContext::set(log::LogLevel new_log_level)
{
    log_level = new_log_level;
    if ( log_level == log::LogLevel::Debug )
    {
        dbg("Setting DEBUG log level");
    }
}
