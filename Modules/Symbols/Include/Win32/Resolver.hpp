#pragma once

#include "Common.hpp"

namespace pwn::Resolver
{

#if defined(PWN_BUILD_FOR_WINDOWS)
#define ExternalImport(Dll, Func, Ret, ...)                                                                            \
    typedef Ret(NTAPI* CONCAT(pwnFn_, Func))(__VA_ARGS__);                                                             \
    template<typename... Ts>                                                                                           \
    static auto Func(Ts... Args)->Ret                                                                                  \
    {                                                                                                                  \
        static auto fnPtr = (pwnFn_##Func)::GetProcAddress(::GetModuleHandleA(Dll), #Func);                            \
        return fnPtr(std::forward<Ts>(Args)...);                                                                       \
    }
#endif // PWN_BUILD_FOR_WINDOWS


#if defined(PWN_BUILD_FOR_LINUX)
#define ExternalImport(Dll, Func, Ret, ...)                                                                            \
    typedef Ret(NTAPI* CONCAT(pwnFn_, Func))(__VA_ARGS__);                                                             \
    template<typename... Ts>                                                                                           \
    auto Func(Ts... Args)->Ret                                                                                         \
    {                                                                                                                  \
        static auto fnPtr = ::dlsym(::dlopen((Dll, RTLD_LAZY), #Func));                                                \
        return fnPtr(std::forward<Ts>(Args)...);                                                                       \
    }
#endif // PWN_BUILD_FOR_LINUX
};     // namespace Resolver
