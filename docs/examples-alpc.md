
Namespace: `pwn::windows::alpc`


## Server
```cpp
#include <pwn.hpp>

int wmain(int argc, wchar_t** argv)
{
    //
    // Create an ALPC server that will automatically close when it goes out-of-scope
    //
    auto server = pwn::windows::alpc::Server(L"\\RPC Control\\lotzofun");
    if ( !server )
        return EXIT_FAILURE;

    ok(L"ALPC server created on port '{}' (handle={})", server.PortName().c_str(), server.SocketHandle());

    //
    // Wait for a client
    //
    HANDLE hClient = INVALID_HANDLE_VALUE;
    {
        auto res = server.Accept();
        if(Failed(res))
            return EXIT_FAILURE;

        hClient = Value(res);
    }

    //
    // Create a simple REPL
    //
    while(true)
    {
        auto res = server.SendAndReceive(hClient, {});
        if( Failed(res) )
            break;

        auto msg = Value(res);
        info("new message received, {} bytes", msg.size());
        if(std::memcmp(msg.data(), "quit", 4) == 0)
            break;

        pwn::utils::hexdump(msg);

        server.SendAndReceive(hClient, {'O', 'K'});
    }

    // You can also use `pwn::windows::alpc::close(server);` to close the socket at any time

    return EXIT_SUCCESS;
}
```


## Client

```cpp
#include <pwn.hpp>

int wmain(int argc, wchar_t** argv)
{
    //
    // Create an ALPC client that will automatically close when it goes out-of-scope
    //
    auto client = pwn::windows::alpc::Client(L"\\RPC Control\\lotzofun");
    if ( !client )
        return EXIT_FAILURE;

    ok(L"client connected to epmapper (handle=%p)\n", client.SocketHandle());
    client.sr({ 'A', 'B', 'C', 'D' });

    // You can also use `pwn::windows::alpc::close(client);` to close the socket at any time

    pwn::utils::Pause();
    return EXIT_SUCCESS;
}
```
