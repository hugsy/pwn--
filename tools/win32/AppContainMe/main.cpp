/*++

Example file to create a simple AppContainer for containing any PE binary.

--*/

#include <exception>
#include <filesystem>
#include <iostream>
#include <pwn.hpp>

namespace ctx = pwn::context;


auto
wmain(_In_ int argc, _In_ const wchar_t** argv) -> int
{
    if ( argc < 2 )
    {
        err(L"Syntax\n\t{} PROCESS [ARG1 [ARG2...]] [d:\\allowed\\path1 d:\\allowed\\path2] [c:Capability1 "
            L"c:Capability2]\n",
            argv[0]);
        return EXIT_FAILURE;
    }

    pwn::globals.set("x64");
    pwn::globals.log_level = pwn::log::log_level_t::LOG_DEBUG;

    const std::wstring containerName {L"appcontainer-" + pwn::utils::random::alnum(10)};
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

            dbg(L"building container '{}'...\n", containerName);

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
                        info(L"adding capability '{}'...\n", name);
                        capabilities.push_back(std::get<1>(cap));
                    }
                }
            }


            //
            // initialize the appcontainer with the given capabilities
            //
            pwn::windows::process::appcontainer::AppContainer app(containerName, processName, capabilities);

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
                            warn(L"Skipping {}...\n", std::filesystem::absolute(value).c_str());
                            continue;
                        }

                        //
                        // appcontainers only allow explicit access to objects
                        //
                        info(L"trying to add access to file/directory '{}'...\n", value.c_str());
                        if ( !app.allow_file_or_directory(std::filesystem::absolute(value).c_str()) )
                        {
                            pwn::log::perror(L"allow_file_or_directory()");
                            break;
                        }
                        else
                        {
                            ok(L"added!\n");
                        }

                        continue;
                    }

                    if ( arg.starts_with(L"r:") )
                    {
                        std::wstring value(arg.substr(2));
                        //
                        // add access to registry
                        //
                        info(L"trying to add access to registry '{}'...\n", value);
                        if ( !app.allow_registry_key(value) )
                        {
                            pwn::log::perror(L"allow_registry_key()");
                            break;
                        }
                        else
                        {
                            ok(L"added!\n");
                        }
                    }
                }
            }


            ok(L"spawing process '{}'\n", processName);

            if ( !app.spawn() )
            {
                err(L"failed to launch '{}'\n", processName);
                pwn::log::perror(L"appcontainer::spawn()");
                return EXIT_FAILURE;
            }

            app.join();
            app.restore_acls();
        } while ( 0 );
    }
    catch ( std::runtime_error& e )
    {
        err(L"container initialization failed: {}\n", pwn::utils::to_widestring(e.what()));
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
