///
///@file AppContainMe.cpp
///@author hugsy (hugsy@blah.cat)
///@brief Example file to create a simple AppContainer for containing any PE binary.
///@version 0.1
///
///@copyright Copyright (c) 2023
///

#include <exception>
#include <filesystem>
#include <iostream>

#include "pwn.hpp"
using namespace pwn;

auto
wmain(_In_ int argc, _In_ const wchar_t** argv) -> int
{
    if ( argc < 2 )
    {
        err(L"Syntax\t{} PROCESS [ARG1 [ARG2...]] [d:\\allowed\\path1 d:\\allowed\\path2] [c:Capability1 "
            L"c:Capability2]",
            argv[0]);
        return EXIT_FAILURE;
    }

    Context.Set("x64");
    Context.LogLevel = Log::LogLevel::Debug;

    const std::wstring containerName {L"appcontainer-" + Utils::Random::alnum(10)};
    const std::wstring processName {argv[1]};
    const std::vector<std::tuple<std::wstring, WELL_KNOWN_SID_TYPE> > AvailableCapabilities = {
        {L"InetClient", WinCapabilityInternetClientSid},
        {L"InetServer", WinCapabilityInternetClientServerSid},
        {L"LocalNet", WinCapabilityPrivateNetworkClientServerSid},
        // todo add more
    };

    try
    {
        do
        {

            dbg(L"building container '{}'...", containerName);

            //
            // collect the capabilities we'll allow to the appcontainer
            //
            std::vector<WELL_KNOWN_SID_TYPE> capabilities;

            for ( int i = 2; i < argc; i++ )
            {
                std::wstring arg {argv[i]};
                if ( arg.starts_with(L"c:") == false )
                    continue;

                std::wstring value(arg.substr(2));

                for ( auto& cap : AvailableCapabilities )
                {
                    auto& name = std::get<0>(cap);
                    if ( name == value )
                    {
                        info(L"adding capability '{}'...", name);
                        capabilities.push_back(std::get<1>(cap));
                    }
                }
            }


            //
            // initialize the appcontainer with the given capabilities
            //
            Process::AppContainer app(containerName, processName, capabilities);

            if ( argc >= 3 )
            {
                for ( int i = 2; i < argc; i++ )
                {
                    std::wstring arg {argv[i]};

                    if ( arg.starts_with(L"d:") )
                    {
                        const std::filesystem::path value(arg.substr(2));
                        if ( !std::filesystem::is_regular_file(value) && !std::filesystem::is_directory(value) )
                        {
                            warn(L"Skipping {}...", std::filesystem::absolute(value).c_str());
                            continue;
                        }

                        //
                        // appcontainers only allow explicit access to objects
                        //
                        info(L"trying to add access to file/directory '{}'...", value.c_str());
                        if ( !app.AllowFileOrDirectory(std::filesystem::absolute(value).c_str()) )
                        {
                            Log::perror(L"AllowFileOrDirectory()");
                            break;
                        }
                        else
                        {
                            ok(L"added!");
                        }

                        continue;
                    }

                    if ( arg.starts_with(L"r:") )
                    {
                        std::wstring value(arg.substr(2));
                        //
                        // add access to registry
                        //
                        info(L"trying to add access to registry '{}'...", value);
                        if ( !app.AllowRegistryKey(value) )
                        {
                            Log::perror(L"AllowRegistryKey()");
                            break;
                        }
                        else
                        {
                            ok(L"added!");
                        }
                    }
                }
            }


            ok(L"spawing process '{}'", processName);

            if ( !app.Spawn() )
            {
                Log::perror(L"appcontainer::Spawn()");
                return EXIT_FAILURE;
            }

            app.Join();
            app.RestoreAcls();
        } while ( 0 );
    }
    catch ( std::runtime_error& e )
    {
        err(L"container initialization failed: {}", Utils::StringLib::To<std::wstring, std::string>(e.what()));
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
