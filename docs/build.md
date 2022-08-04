# Build with `pwn++`

## From Github template

Simply clone from the repository [template-pwn](https://github.com/hugsy/template-pwn). It will set you up for building your new project against `pwn++` through Cmake.

```bash
git clone https://github.com/hugsy/template-pwn /path/to/my/dir
```

This will create a minimal environment for `cmake` to run. Note that you may have to edit `pwn++/CMakeLists.txt` and turn off the external dependencies for compilation, or it will fail to build correctly.

To get an environment ready to compile with all external dependencies, add the `--recure-submodules` flag:

```bash
git clone --recurse-submodules https://github.com/hugsy/template-pwn /path/to/my/dir
```


## Using the pre-builds

To start using `pwn++` lib, simply download the latest successful build from [CI builds](https://github.com/hugsy/pwn--/actions/workflows/msvc-build.yml?query=is%3Asuccess), download and extract the zip file.
In your C++ file, just include `pwn.h` and link with `pwn++.dll`.

```cpp
#include "path\to\pwn++\pwn.h"
#pragma comment(lib, "\path\to\pwn++\pwn.lib")
```

Then compile your binary linked with the lib (make sure you're at least C++17 compliant):

```bash
C:\> cl.exe whatever.cc /std:c++20
C:\> clang.exe whatever.cc -std=c++20
```
