#pragma once

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
    format(std::wstring wstr, PwnFormatContext& ctx)
    {
        return PwnFormatter<std::string>::format(PwnFormat("{}", Utils::StringLib::To<std::string>(wstr)), ctx);
    }
};


template<>
struct PwnFormatter<Err, char> : PwnFormatter<std::string, char>
{
    auto
    format(Err const a, PwnFormatContext& ctx)
    {
        std::ostringstream os;
        os << a;
        return PwnFormatter<std::string, char>::format(os.str().c_str(), ctx);
    }
};


template<>
struct PwnFormatter<ErrorType, char> : PwnFormatter<std::string, char>
{
    auto
    format(ErrorType const a, PwnFormatContext& ctx)
    {
        std::ostringstream os;
        os << a;
        return PwnFormatter<std::string, char>::format(os.str().c_str(), ctx);
    }
};
