
<p align="center">
  <img src="https://i.imgur.com/39XyWFo.png" alt="logo" title="logo pwn++" width=35% />
</p>

<h2 align="center"><code>#include &lt;pwn&gt;</code></h2>

<p align="center">
  <a href="https://hugsy.github.io/pwn--"><img alt="Docs" src="https://img.shields.io/badge/Docs-gh--pages-darkgreen"></a>
  <a href="https://discord.gg/5HmwPxy3HP"><img alt="Discord" src="https://img.shields.io/badge/Discord-BlahCats-yellow"></a>
  <a href="https://github.dev/hugsy/pwn--"><img alt="Read Code" src="https://img.shields.io/badge/Code-Read%20pwn++-brightgreen?logo=visualstudiocode"></a>
  <a href="https://open.vscode.dev/hugsy/pwn--"><img alt="Open in VSCode" src="https://img.shields.io/static/v1?logo=visualstudiocode&label=&message=Open%20in%20VSCode&labelColor=2c2c32&color=007acc&logoColor=007acc"></a>
  <a href="https://github.com/hugsy/pwn--/actions?query=workflow%3A%22CI+Build+for+MSVC%22"><img alt="CI" src="https://github.com/hugsy/pwn--/workflows/CI%20Build%20for%20MSVC/badge.svg"></a>
</p>

## Quick start

### Template

Git-Clone the template in [`hugsy/template-pwn`](https://github.com/hugsy/pwn--template)

### CMake

```cmake
include(FetchContent)
FetchContent_Declare(
    pwn++
    GIT_REPOSITORY https://github.com/hugsy/pwn--.git
    GIT_TAG main # or whatever other tag
)
FetchContent_MakeAvailable(pwn++)
```

## What is it?

A poor rewrite of my [PwnLib](https://github.com/hugsy/pwnlib) DLL in modern C++, battery-included pwn kit for Windows (and a bit for Linux).

## Why?

Because:
  - I wanted a quick way to bootstrap my low-level experiments
  - it's unacceptable to struggle every time I need a `hexdump`-like function
  - modern C++ allows to do crazy useful offsec stuff, completely underused
  - I like writing code

The idea is to provide in C on Windows the same kind of functionalities than [pwntools](https://github.com/Gallopsled/pwntools) does in Python on Linux. It's also a toy library meant for exploring Windows in a more friendly way. So if you're looking for years of poorly written C++ tangled with performant inefficient ways to experiment low-level, go no further friend this library is for you.

_Note_: the original `PwnLib` was written around Windows 7 for feature testing. This is 100% Windows 10/11 focused, so expect things to go wrong if you use any other Windows version. Some stuff may also go wrong in x86. Better use 64. It's not a bug but a design choice 😋
