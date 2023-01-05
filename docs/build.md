# Build with `pwn++`

## From the Github `template-pwn` *(preferred)*

A Github template repository was created, [template-pwn](https://github.com/hugsy/template-pwn), to make things easier. It will set you up for building your new project against `pwn++` through Cmake.

```bash
git clone --recurse-submodules https://github.com/hugsy/template-pwn MyProject
```

This will create a minimal environment for `cmake` to run. Note that you may have to edit `pwn++/CMakeLists.txt` and turn off the external dependencies for compilation, or it will fail to build correctly.

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

