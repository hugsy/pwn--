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
        err(L"Missing process name\n");
        return EXIT_FAILURE;
    }

    const std::wstring containerName = L"my-awesome-container-1234567";
    const std::wstring processName = argv[1];

    try
    {
        do
        {
            //
            // create the appcontainer
            //
            pwn::process::appcontainer::AppContainer app(containerName, processName);

            if (argc >= 3)
            {
                for (int i = 2; i < argc; i++)
                {
                    std::wstring arg = argv[i];

                    if (pwn::utils::startswith(arg, std::wstring(L"d:")))
                    {
                        std::wstring value(arg.substr(2));
                        //
                        // appcontainers only allow explicit access to objects
                        //
                        info(L"trying to add access to '%s'...\n", value.c_str());
                        if (!app.allow_file_or_directory(value))
                        {
                            perror(L"allow_file_or_directory()");
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