#include <pwn.hpp>
using namespace pwn;

auto
wmain(int argc, const wchar_t** argv) -> int
{
    if ( argc < 2 )
    {
        err(L"Missing file name");
        return EXIT_FAILURE;
    }

    auto hFile      = ValueOr<HANDLE>(FileSystem::File::Open(argv[1]), nullptr);
    auto TargetFile = FileSystem::File(std::move(hFile));
    auto sz         = ValueOr(TargetFile.Size(), (usize)0);
    auto res        = TargetFile.ToBytes(0, sz);
    if ( Success(res) )
    {
        auto bytes = Value(std::move(res));
        Utils::Hexdump(bytes);
    }

    return EXIT_SUCCESS;
}
