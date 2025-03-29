#include <pwn>
using namespace pwn;

auto
wmain(int argc, const wchar_t** argv) -> int
{
    if ( argc < 2 )
    {
        err(L"Missing file name");
        return EXIT_FAILURE;
    }

    auto hFile = FileSystem::File::Open(argv[1]).value_or(nullptr);
    if ( !hFile )
    {
        return EXIT_FAILURE;
    }

    auto TargetFile = FileSystem::File(std::move(hFile));
    auto sz         = TargetFile.Size().value_or((usize)0);
    auto res        = TargetFile.ToBytes(0, sz).and_then(
        [](auto&& bytes) -> Result<int>
        {
            Utils::Hexdump(bytes);
            return Ok(0);
        });

    if ( Failed(res) )
    {
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
