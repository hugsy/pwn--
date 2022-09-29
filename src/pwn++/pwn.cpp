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
    const std::string _t {type};
    set(pwn::utils::to_widestring(_t));
}


void
pwn::GlobalContext::set(std::wstring_view const& type)
{
    try
    {
        architecture = lookup_architecture(type);
        endianess    = architecture.endian;
        ptrsize      = architecture.ptrsize;

        dbg(L"Selecting {}", architecture);
    }
    catch ( std::range_error const& e )
    {
        err(L"Invalid architecture '{}'. Value must be in:", type);
        for ( auto const& [name, arch] : Architectures )
        {
            std::wcout << L"- " << std::setw(9) << name << std::endl;
        }
    }
}


void
pwn::GlobalContext::set(Endianess end)
{
    endianess = end;
}

void
pwn::GlobalContext::set(log::log_level_t new_log_level)
{
    log_level = new_log_level;
    if ( log_level == log::log_level_t::LOG_DEBUG )
    {
        dbg(L"Setting DEBUG log level");
    }
}
