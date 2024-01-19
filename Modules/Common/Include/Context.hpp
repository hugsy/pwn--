#pragma once

#include "Architecture.hpp"
#include "Common.hpp"
#include "Log.hpp"
#include "Utils.hpp"

using namespace pwn;

///
/// @brief Global context definition
///
class GlobalContext
{
public:
    u64 CryptoSeed;
    std::mutex m_ConsoleMutex;
    std::mutex m_ConfigMutex;
    Log::LogLevel LogLevel = Log::LogLevel::Info;

    Architecture architecture;
    Endianess endianess;
    usize ptrsize;

    GlobalContext();


    template<typename T>
    void
    Set(T const& arg)
    {
        if constexpr ( std::is_same_v<T, std::string_view> )
        {
            warn("Deprecated, prefer using ArchitectureType");
            SetArchitecture(arg);
            return;
        }

        if constexpr ( std::is_same_v<T, std::wstring_view> )
        {
            warn("Deprecated, prefer using ArchitectureType");
            SetArchitecture(Utils::StringLib::To<std::string>(arg));
            return;
        }

        if constexpr ( std::is_same_v<T, ArchitectureType> )
        {
            SetArchitecture(arg);
            return;
        }

        if constexpr ( std::is_same_v<T, Log::LogLevel> )
        {
            SetLogLevel(arg);
            return;
        }

        if constexpr ( std::is_same_v<T, Endianess> )
        {
            SetEndianess(arg);
            return;
        }

        throw new std::bad_typeid();
    }


private:
    ///
    /// @brief Set the Architecture for the global context
    ///
    /// @param arch
    ///
    void
    SetArchitecture(ArchitectureType const& arch);


    ///
    ///@brief Set the Architecture object from its name
    ///
    ///@param type
    ///
    void
    SetArchitecture(std::string_view const& type);


    ///
    ///@brief Force the endianess on the selected architecture. Note that this will impact function that automatically
    /// collect context info to determine their behavior (for instance `Utils::Pack` etc.)
    ///
    ///@param end
    ///
    void
    SetEndianess(Endianess end);


    ///
    ///@brief Set the Log Level object
    ///
    ///@param new_log_level
    ///
    void SetLogLevel(Log::LogLevel);
};


extern struct GlobalContext Context;
