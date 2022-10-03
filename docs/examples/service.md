## Service

Namespace: `pwn::windows::service`

### Enumerate

```cpp
#include <pwn++\pwn.h>

void wmain()
{
    for ( auto service : pwn::service::list() )
    {
        ok(L"Name='%s' Display='%s' Type=%d Status=%d\n",
            service.Name.c_str(),
            service.DisplayName.c_str(),
            service.Type,
            service.Status
        );
    }
}
```

