#include "../pwn++/pwn.h"
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

    const std::wstring containerName = L"my-awesome-container";
    const std::wstring processName = argv[1];

    if (!pwn::process::appcontainer::create_appcontainer(containerName, processName))
        err(L"failed to create %s\n", processName.c_str());

    return EXIT_SUCCESS;
}