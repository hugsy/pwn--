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
struct PwnFormatter<std::wstring> : PwnFormatter<std::string>
{
    auto
    format(std::wstring const& wstr, PwnFormatContext& ctx)
    {
        return PwnFormatter<std::string>::format(PwnFormat("{}", Utils::StringLib::To<std::string>(wstr)), ctx);
    }
};


///
///@brief Error Formatter
///
///@tparam
///
template<>
struct PwnFormatter<Err, char> : PwnFormatter<std::string, char>
{
    auto
    format(Err const& err, PwnFormatContext& ctx)
    {
        std::stringstream os;
        // os << "Error("sv << err.Code << ")";
        // if ( err.LastError )
        // {
        //     os << " - " << Log::FormatLastError<std::string>(err.LastError);
        // }
        os << '\n';
        return PwnFormatter<std::string, char>::format(os.str().c_str(), ctx);
    }
};
