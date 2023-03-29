///
/// @file Backdoor
///
/// @author hugsy (hugsy [AT] blah [DOT] cat)
///
/// @brief
///

#include <pwn.hpp>
using namespace pwn;


auto
wmain(const int argc, const wchar_t** argv) -> int
{
    Context.Set(Log::LogLevel::Debug);

    Utils::Random::seed();

    info(L"Starting backdoor thread");
    {
        auto res = Backdoor::start();
        if ( Failed(res) )
        {
            err(L"Couldn't start backdoor thread");
            exit(EXIT_FAILURE);
        }
    }

    Utils::Pause();

    Backdoor::stop();

    return EXIT_SUCCESS;
}
