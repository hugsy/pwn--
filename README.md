<p align="center">
  <h1> pwn++ </h1>
</p>

<p align="center">
  <img src="https://i.imgur.com/39XyWFo.png" alt="logo" title="logo pwn++" />
</p>

<p align="center">
  <a href="https://hugsy.github.io/pwn--"><img alt="Docs" src="https://img.shields.io/badge/Docs-gh--pages-darkgreen"></a>
  <a href="https://discord.gg/5HmwPxy3HP"><img alt="Discord" src="https://img.shields.io/badge/Discord-BlahCats-yellow"></a>
  <a href="https://github.dev/hugsy/pwn--"><img alt="Read Code" src="https://img.shields.io/badge/Code-Read%20pwn++-brightgreen?logo=visualstudiocode"></a>
  <a href="https://open.vscode.dev/hugsy/pwn--"><img alt="Open in VSCode" src="https://img.shields.io/static/v1?logo=visualstudiocode&label=&message=Open%20in%20VSCode&labelColor=2c2c32&color=007acc&logoColor=007acc"></a>
  <a href="https://github.com/hugsy/pwn--/actions?query=workflow%3A%22CI+Build+for+MSVC%22"><img alt="CI" src="https://github.com/hugsy/pwn--/workflows/CI%20Build%20for%20MSVC/badge.svg"></a>
</p>


A rewrite of my [PwnLib](https://github.com/hugsy/pwnlib) DLL in modern C++, battery-included pwn kit for Windows (and a bit for Linux).

The idea is to provide in C on Windows the same kind of functionalities than [pwntools](https://github.com/Gallopsled/pwntools) does in Python on Linux.
It's also a toy library meant for exploring Windows in a more friendly way. So if you're looking for years of poorly written C/C++ tangled with performant
inefficient ways to explore Windows at low-level, go no further friend this library is for you.

_Note_: the original `PwnLib` was written around Windows 7 for feature testing. This is 100% Windows 10/11 focused, so expect things to go wrong if you use any other Windows version. Some stuff may also go wrong in x86. Better use 64. It's not a bug but a design choice 😋
