#include "pwn.hpp"


PWNAPI struct pwn::GlobalContext pwn::Context;

pwn::GlobalContext::GlobalContext()
{
    pwn::utils::random::seed(std::chrono::system_clock::now().time_since_epoch().count());
#if PWN_BUILD_ARCHITECTURE == "x86"
    set("x86");
#elif PWN_BUILD_ARCHITECTURE == "arm64"
    set("arm64");
#else
    set("x64");
#endif
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
