#include "Context.hpp"

#include "Architecture.hpp"
#include "Formatters.hpp"

using namespace pwn;

struct GlobalContext Context;

GlobalContext::GlobalContext()
{
    Utils::Random::Seed(std::chrono::system_clock::now().time_since_epoch().count());
    Set(ArchitectureType::x64);
};

void
GlobalContext::SetArchitecture(ArchitectureType const& archtype)
{
    auto arch    = Architectures.at(archtype);
    architecture = arch;
    endianess    = arch.endian;
    ptrsize      = arch.ptrsize;
    dbg("Selecting '{}'", arch);
}

void
GlobalContext::SetArchitecture(std::string_view const& type)
{
    auto arch    = Architecture::Find(type);
    architecture = arch;
    endianess    = arch.endian;
    ptrsize      = arch.ptrsize;
    dbg("Selecting '{}'", arch);
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
