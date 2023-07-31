#pragma once

#include <unordered_map>

#include "Common.hpp"
namespace pwn::Resolver
{

#if defined(PWN_BUILD_FOR_WINDOWS)
static std::unordered_map<std::string_view, HMODULE> pwn_Modules {};

#define ExternalImport(Dll, Func, Ret, ...)                                                                            \
    typedef Ret(NTAPI* CONCAT(pwnFn_, Func))(__VA_ARGS__);                                                             \
    template<typename... Ts>                                                                                           \
    static auto Func(Ts... Args)->Ret                                                                                  \
    {                                                                                                                  \
        if ( !pwn_Modules.contains(Dll) )                                                                              \
        {                                                                                                              \
            pwn_Modules[Dll] = ::LoadLibraryA(Dll);                                                                    \
        }                                                                                                              \
        static auto fnPtr = reinterpret_cast<pwnFn_##Func>(::GetProcAddress(pwn_Modules[Dll], #Func));                 \
        if ( !fnPtr )                                                                                                  \
        {                                                                                                              \
            throw std::runtime_error("Missing import " Dll "!" #Func);                                                 \
        }                                                                                                              \
        return fnPtr(std::forward<Ts>(Args)...);                                                                       \
    }
#endif // PWN_BUILD_FOR_WINDOWS


#if defined(PWN_BUILD_FOR_LINUX)
static std::unordered_map<std::string_view, int> pwn_Modules {};

#define ExternalImport(Dll, Func, Ret, ...)                                                                            \
    typedef Ret(NTAPI* CONCAT(pwnFn_, Func))(__VA_ARGS__);                                                             \
    template<typename... Ts>                                                                                           \
    auto Func(Ts... Args)->Ret                                                                                         \
    {                                                                                                                  \
        if ( !pwn_Modules.contains(Dll) )                                                                              \
        {                                                                                                              \
            pwn_Modules[Dll] = ::::dlopen((Dll, RTLD_LAZY);                                                            \
        }                                                                                                              \
        static auto fnPtr = ::dlsym(pwn_Modules[Dll], #Func));                                                         \
        if ( !fnPtr )                                                                                                  \
        {                                                                                                              \
            throw std::runtime_error("Missing import " Dll "!" #Func);                                                 \
        }                                                                                                              \
        return fnPtr(std::forward<Ts>(Args)...);                                                                       \
    }
#endif // PWN_BUILD_FOR_LINUX

};     // namespace pwn::Resolver


#define RestrictedType(...) const auto& __VA_OPT__(, RestrictedType(__VA_ARGS__))
#define RestrictApiType(Ret, Func, ...) Ret Func()
