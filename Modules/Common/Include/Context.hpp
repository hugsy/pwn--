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
#ifdef PWN_INCLUDE_BACKDOOR
    std::jthread m_backdoor_thread;
    std::vector<std::shared_ptr<Backdoor::ThreadConfig>> m_backdoor_clients;
#endif
    u64 m_seed;
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
            SetArchitecture(arg);
            return;
        }

        if constexpr ( std::is_same_v<T, std::wstring_view> )
        {
            SetArchitecture(Utils::StringLib::To<std::string>(arg));
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

    void
    Set(const char* arg)
    {
        return Set(std::string_view(arg));
    }


private:
    ///
    ///@brief Set the Architecture object
    ///
    ///@param type
    ///
    void
    SetArchitecture(std::string_view const& type);


    ///
    ///@brief Set the Endianess object
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
