#pragma once


#include <format>
#include <string>

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
    format(std::wstring wstr, format_context& ctx)
    {
        return formatter<std::string>::format(std::format("{}", Utils::StringLib::To<std::string>(wstr)), ctx);
    }
};


template<>
struct std::formatter<Err, char> : std::formatter<std::string, char>
{
    auto
    format(Err const a, format_context& ctx)
    {
        std::ostringstream os;
        os << a;
        return std::formatter<string, char>::format(os.str().c_str(), ctx);
    }
};


template<>
struct std::formatter<ErrorType, char> : std::formatter<std::string, char>
{
    auto
    format(ErrorType const a, format_context& ctx)
    {
        std::ostringstream os;
        os << a;
        return std::formatter<string, char>::format(os.str().c_str(), ctx);
    }
};
