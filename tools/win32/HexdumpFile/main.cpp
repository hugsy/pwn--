#include <pwn.hpp>

using namespace pwn::log;

#include <vector>


auto
wmain(_In_ int argc, _In_ const wchar_t** argv) -> int
{
    if ( argc < 2 )
    {
        err(L"Missing process name\n");
        return EXIT_FAILURE;
    }

    auto h =
        pwn::UniqueHandle(::CreateFile(argv[1], GENERIC_READ, 0, nullptr, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr));
    if ( h )
    {
        auto sz = ::GetFileSize(h.get(), nullptr);
        std::vector<u8> bytes(sz);
        DWORD dummy;
        if ( ::ReadFile(h.get(), bytes.data(), sz, &dummy, nullptr) )
            pwn::utils::hexdump(bytes);
    }
    else
    {
        perror(L"CreateFile()");
    }

    return EXIT_SUCCESS;
}
