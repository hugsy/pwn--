#pragma once

#include <sstream>
#include <string>

#include "Log.hpp"
#include "Utils.hpp"

using namespace pwn;

///
///@brief Wide string formatter
///
///@tparam
///
template<>
struct std::formatter<std::wstring> : std::formatter<std::string>
{
    auto
    format(std::wstring const& wstr, std::format_context& ctx)
    {
        return std::formatter<std::string>::format(std::format("{}", Utils::StringLib::To<std::string>(wstr)), ctx);
    }
};


///
///@brief Error Formatter
///
///@tparam
///
template<>
struct std::formatter<Error, char> : std::formatter<std::string, char>
{
    auto
    format(Error const& err, std::format_context& ctx)
    {
        std::stringstream os;
        // os << "Error("sv << err.Code << ")";
        // if ( err.LastError )
        // {
        //     os << " - " << Log::FormatLastError<std::string>(err.LastError);
        // }
        os << '\n';
        return std::formatter<std::string, char>::format(os.str().c_str(), ctx);
    }
};
