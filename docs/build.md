# Build with `pwn++`

## From Github *(preferred)*

To get an environment ready to compile with all external dependencies, clone this repository - and don't forget to add the `--recure-submodules` flag:

```bash
cd <YourProject/libs>
git clone --recurse-submodules https://github.com/hugsy/pwn--
```

## From Github template

A Github template repository was created, [template-pwn](https://github.com/hugsy/template-pwn), to make things easier. It will set you up for building your new project against `pwn++` through Cmake.

```bash
git clone --recurse-submodules https://github.com/hugsy/template-pwn /path/to/my/dir
```

This will create a minimal environment for `cmake` to run. Note that you may have to edit `pwn++/CMakeLists.txt` and turn off the external dependencies for compilation, or it will fail to build correctly.


## Using the CI pre-builds

To start using `pwn++` lib, simply download the latest successful build from [CI builds](https://github.com/hugsy/pwn--/actions/workflows/build.yml?query=is%3Asuccess), download and extract the zip file. Then just include `pwn.hpp` and link against `pwn++.lib`.

```cpp
#include "path\to\pwn++\pwn.hpp"
#pragma comment(lib, "\path\to\pwn++\pwn.lib")
```

Then compile your binary linked with the library (make sure you're at least C++20 compliant):

```bash
C:\> cl.exe whatever.cc /std:c++20
C:\> clang.exe whatever.cc -std=c++20
```
