#include "Context.hpp"

#include "Formatters.hpp"

using namespace pwn;

struct GlobalContext Context;

GlobalContext::GlobalContext()
{
    Utils::Random::Seed(std::chrono::system_clock::now().time_since_epoch().count());
    Set("x64");
};


void
GlobalContext::SetArchitecture(std::string_view const& type)
{
    architecture = Architecture::Find(type);
    endianess    = architecture.endian;
    ptrsize      = architecture.ptrsize;
    dbg("Selecting '{}'", architecture);
}


void
GlobalContext::SetEndianess(Endianess end)
{
    endianess = end;
}


void
GlobalContext::SetLogLevel(Log::LogLevel new_log_level)
{
    LogLevel = new_log_level;
    if ( LogLevel == Log::LogLevel::Debug )
    {
        dbg("Setting DEBUG log level");
    }
}
