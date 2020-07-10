#include "../pwn++/pwn.h"

#include <iostream>
#include <exception>

#pragma comment(lib, "../x64/release/pwn++.lib")

using namespace pwn::log;

namespace ctx = pwn::context;


auto wmain(_In_ int argc, _In_ const wchar_t** argv) -> int
{
    if (argc < 2)
    {
        err(L"syntax\n\t%s 'process_to_run.exe arg1 arg2' [d:\\allowed\\path1 d:\\allowed\\path2] [c:Capability1 c:Capability2]\n");
        return EXIT_FAILURE;
    }

    ctx::set_log_level(log_level_t::LOG_DEBUG);

    const std::wstring containerName{L"appcontainer-" + pwn::utils::random::alnum(10)};
    const std::wstring processName = argv[1];
    const std::vector< std::tuple<std::wstring, WELL_KNOWN_SID_TYPE>> AvailableCapabilities =
    {
        {L"InetClient", WinCapabilityInternetClientSid},
        {L"InetServer", WinCapabilityInternetClientServerSid},
        {L"LocalNet", WinCapabilityPrivateNetworkClientServerSid},
        // todo add more
    };

    try
    {
        do
        {

            dbg(L"building container '%s'...\n", containerName.c_str());

            //
            // collect the capabilities we'll allow to the appcontainer
            //
            std::vector<WELL_KNOWN_SID_TYPE> capabilities;

            for (int i = 2; i < argc; i++)
            {
                std::wstring arg{ argv[i] };
                if (!pwn::utils::startswith(arg, L"c:"))
                    continue;

                std::wstring value(arg.substr(2));

                for (auto& cap : AvailableCapabilities)
                {
                    auto name = std::get<0>(cap);
                    if (name == value)
                    {
                        info(L"adding capability '%s'...\n", name.c_str());
                        capabilities.push_back(std::get<1>(cap));
                    }
                }
            }


            //
            // initialize the appcontainer with the given capabilities
            //
            pwn::process::appcontainer::AppContainer app(containerName, processName, capabilities);

            if (argc >= 3)
            {
                for (int i = 2; i < argc; i++)
                {
                    std::wstring arg{ argv[i] };

                    if (pwn::utils::startswith(arg, std::wstring(L"d:")))
                    {
                        std::wstring value(arg.substr(2));
                        //
                        // appcontainers only allow explicit access to objects
                        //
                        info(L"trying to add access to file/directory '%s'...\n", value.c_str());
                        if (!app.allow_file_or_directory(value))
                        {
                            perror(L"allow_file_or_directory()");
                            break;
                        }
                        else
                        {
                            ok(L"added!\n");
                        }

                        continue;
                    }

                    if (pwn::utils::startswith(arg, std::wstring(L"r:")))
                    {
                        std::wstring value(arg.substr(2));
                        //
                        // add access to registry
                        //
                        info(L"trying to add access to registry '%s'...\n", value.c_str());
                        if (!app.allow_registry_key(value))
                        {
                            perror(L"allow_registry_key()");
                            break;
                        }
                        else
                        {
                            ok(L"added!\n");
                        }
                    }
                }
            }


            ok(L"spawing process '%s'\n", processName.c_str());

            if (!app.spawn())
            {
                err(L"failed to launch '%s'\n", processName.c_str());
                perror(L"appcontainer::spawn()");
                return EXIT_FAILURE;
            }

            app.join();
            app.restore_acls();
        } 
        while (0);
    }
    catch (std::runtime_error& e)
    {
        err(L"container initialization failed: %S\n", e.what());
        return EXIT_FAILURE;
    }
    
    return EXIT_SUCCESS;
}