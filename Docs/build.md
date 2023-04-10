# Build with `pwn++`

_Note_: `pwn++` is using many features of modern C++20, some of which have not been fully integrated by some compilers. Therefore we recommend to use VisualStudio 2022 to build it.


## From the Github `template-pwn` *(preferred)*

A Github template repository was created, [template-pwn](https://github.com/hugsy/template-pwn), to make things easier. It will set you up for building your new project against `pwn++` through Cmake.

```bash
git clone --recurse-submodules https://github.com/hugsy/template-pwn MyProject
cd MyProject
mkdir build
cd build
cmake ..
cmake --build . --verbose --config Release
```

_Note_: The pattern `ChangeMe` is used as a placeholder in several locations of the template. Replace it to your project name.

This will create a binary with (by default) the minimal parts of `pwn++` set. To extend the features, you can either:
 - edit the `CMakeLists.txt` and turn on/off the external dependencies for compilation, should you need/don't need them ;
 - provide the specific wanted options directly when invoking `cmake`, for instance to enable the X86/X64 disassembler support:

```bash
cmake .. -DPWN_DISASSEMBLE_X86=ON
```


## From Github

To get an environment ready to compile with all external dependencies, clone this repository - and don't forget to add the `--recure-submodules` flag:

```bash
cd <YourProject/libs>
git clone --recurse-submodules https://github.com/hugsy/pwn--
```

## As a submodule to your project

Last, `pwn++` can be added to any project as a regular git submodule as such:

```
cd MyProject
mkdir deps
git submodule add 'https://github.com/hugsy/pwn--' deps/pwn++
git submodule update --init --recursive
```

