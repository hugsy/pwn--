
## ALPC

Namespace: `pwn::windows::alpc`


### Server
```cpp
#include <pwn++\pwn.h>

void wmain()
{
    auto server = pwn::UniqueHandle(
        pwn::windowsdows::alpc::server::listen(L"\\RPC Control\\lotzofun")
    );

    if ( server )
    {
        ok(L"server created port (handle=%p)\n", server.Get());
        auto recv = pwn::windowsdows::alpc::send_and_receive(server.Get());
        // pwn::windowsdows::alpc::close(server); // not necessary because of RAII
    }
}
```


### Client

```cpp
#include <pwn++\pwn.h>

void wmain()
{
    auto client = pwn::UniqueHandle(
        pwn::windowsdows::alpc::client::connect(L"\\RPC Control\\lotzofun")
    );

    if ( client )
    {
        ok(L"client connected to epmapper (handle=%p)\n", client.Get());
        pwn::windowsdows::alpc::send_and_receive(client, { 0x41, 0x41, 0x41, 0x41 });
        // pwn::windowsdows::alpc::close(client); // not necessary because of RAII
    }
}
```
