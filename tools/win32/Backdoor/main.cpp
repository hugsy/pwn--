///
/// @file Backdoor
///
/// @author hugsy (hugsy [AT] blah [DOT] cat)
///
/// @brief
///

#include <pwn.hpp>

using namespace std::chrono_literals;


auto
wmain(const int argc, const wchar_t** argv) -> int
{
    pwn::globals.set(pwn::log::log_level_t::LOG_DEBUG);

    pwn::utils::random::seed();

    //
    // Start the backdoor thread
    //
    info(L"Starting backdoor thread");
    {
        // pwn::globals.m_backdoor_thread = std::jthread::jthread(
        //     []
        //     {
        auto res = pwn::backdoor::start();
        if ( Failed(res) )
        {
            err(L"Couldn't start backdoor thread");
            exit(EXIT_FAILURE);
        }
        // });

        // pwn::globals.m_backdoor_thread.detach();
    }

    //
    // Enter to exit
    //
    // pwn::utils::pause();
    std::this_thread::sleep_for(1000s);

    //
    // Stop the thread
    //
    pwn::backdoor::stop();


    return EXIT_SUCCESS;
}
